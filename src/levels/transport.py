import threading
import time
import hashlib

from levels.packet import TransportPacket
from levels.base import Base


class Transport(Base):


    def __init__(self):
        super().__init__()

        # Словарь отправленных пакетов, ждущие подтверждения получения
        self.PENDING_ACK_PACKS = {}
        self.PENDING_ACK_PACKS_LOCK = threading.Lock()

        # Сколько секунд прошло с получения последнего пакета
        self.TIME_SINCE_LAST_PACKET = 0
        self.TIME_SINCE_LAST_PACKET_LOCK = threading.Lock()

        # Потоки байтов которые мы ожидаем
        # ID потока: {count: количество пакетов в данном потоке, packets: [массив полученных пакетов в потоке]}
        self.WAITING_STREAMS = {}

        # Текущий STREAM ID. Нужен для нумерации потоков байт
        self.CURRENT_STREAM_ID = 0

        # Размер чанков данных в байтах
        self.CHUNK_SIZE = 100

        threading.Thread(target=self.every_second).start()


    # Третий поток, каждую секунду выполняющий что-либо
    def every_second(self):
        while not self.stop_event.is_set():

            # Если больше 30 секунд от собеседника не приходило ни одного пакета, то отправляем пинг
            if self.TIME_SINCE_LAST_PACKET > 30:
                self.send_with_pending_ping()

            # Прибавляем единицу, чтобы понимать сколько прошло секунд с получения последнего пакета
            with self.TIME_SINCE_LAST_PACKET_LOCK:
                self.TIME_SINCE_LAST_PACKET += 1

            time.sleep(1)


    # Отправка ping, для проверки доступности собеседника, и ожидание ответа
    def send_with_pending_ping(self):

        self.send_ping()

        timeout = 30
        while self.TIME_SINCE_LAST_PACKET > 30 and not self.stop_event.is_set():

            self.logger.info(f"wait response ping")

            if timeout <= 0:
                # Собеседник не отвечает на пинг 30 секунд
                self.logger.info(f"companion is not responding to ping for more than 30 seconds")
                self.core.on_ping_timeout()
                break

            timeout -= 0.5
            time.sleep(0.5)

        if self.TIME_SINCE_LAST_PACKET <= 30 and not self.stop_event.is_set():
            # Все нормально, собедник на месте. Ничего не делаем
            self.logger.info(f"companion is response to ping")
            pass


    def send_ping(self, response=False):

        if response:
            packet = TransportPacket(0x3, 0, 0, 0, int(time.time()), b'')
        else:
            packet = TransportPacket(0x2, 0, 0, 0, int(time.time()), b'')
        raw_packet_bytes = packet.to_bytes()

        self.logger.info(f"send ping")
        self.LOWER_LEVEL.send(raw_packet_bytes)


    # Отправка подтверждения о получении пакета
    def send_acknowledgment(self, rec_raw_packet_bytes):

        hasher = hashlib.sha256()
        hasher.update(rec_raw_packet_bytes)
        packet_hash = hasher.hexdigest()

        packet = TransportPacket(0x1, 0, 0, 0, int(time.time()), packet_hash.encode())
        raw_packet_bytes = packet.to_bytes()

        self.logger.info(f"send ack for '{packet_hash}'")
        self.LOWER_LEVEL.send(raw_packet_bytes)


    # Отправляем пакет и ожидаем подтверждение его получения
    def send_with_pending_acknowledgment(self, raw_packet_bytes, packet_hash):

        # Повторная отправка выполняется циклом, а не рекурсивным вызовом:
        # на долго недоступном собеседнике рекурсия упиралась в предел глубины
        while not self.stop_event.is_set():

            with self.PENDING_ACK_PACKS_LOCK:
                self.PENDING_ACK_PACKS[packet_hash] = 0

            self.logger.info(f"send packet '{packet_hash}'")
            self.LOWER_LEVEL.send(raw_packet_bytes)

            timeout = False

            while packet_hash in self.PENDING_ACK_PACKS and not self.stop_event.is_set():

                self.logger.info(f"wait ack...")

                with self.PENDING_ACK_PACKS_LOCK:

                    # Подтверждение могло прийти между проверкой в while и захватом замка
                    if packet_hash not in self.PENDING_ACK_PACKS:
                        break

                    if self.PENDING_ACK_PACKS[packet_hash] >= 30:
                        self.logger.warning(f"timeout while wait ack")
                        timeout = True
                        break

                    self.PENDING_ACK_PACKS[packet_hash] = self.PENDING_ACK_PACKS[packet_hash] + 0.5

                time.sleep(0.5)

            if not timeout:
                self.logger.info(f"ack received!")
                return


    # постоянно читает данные из PENDING_PROCESSING_BUF и обрабатывает их и отправляет выше
    def rworker(self, data):

        self.logger.info(f"data received. size: {len(data)}")

        try:
            packet = TransportPacket.from_bytes(data)
        except Exception as e:
            self.logger.error(e)
            return

        if not packet:
            return

        # Проверка на возраст пакета
        difference_seconds = int(time.time()) - packet.time
        # Если пакет старше 5 минут, отбрасываем
        if difference_seconds >= 300:
            self.logger.info(f"old packet. bye")
            return

        # Обнуляем счетчик секунд который означает сколько секунд прошло с момента получения последнего пакета
        with self.TIME_SINCE_LAST_PACKET_LOCK:
            self.TIME_SINCE_LAST_PACKET = 0

        # Если это пакет PING, отправляем ответный PING
        if packet.flags == 0x2:
            self.logger.info(f"receive ping packet. response...")
            self.send_ping(response=True)

        # Если это пакет подтверждения
        if packet.flags == 0x1:

            self.logger.info(f"receive ack packet")

            packet_hash = packet.payload.decode()
            with self.PENDING_ACK_PACKS_LOCK:
                self.PENDING_ACK_PACKS.pop(packet_hash, None)

        # Если просто пакет передачи данных
        if packet.flags == 0x0:

            self.logger.info(f"data packet")

            if packet.stream_id not in self.WAITING_STREAMS:
                self.WAITING_STREAMS[packet.stream_id] = {"count": packet.chunk_count, "packets": {}}

            stream = self.WAITING_STREAMS[packet.stream_id]

            # Чанки хранятся по chunk_id: повторно доставленный чанк
            # (например, при потере подтверждения) не считается новым
            stream["packets"][packet.chunk_id] = packet.payload

            self.logger.info(f"stream {packet.stream_id}: {len(stream['packets'])} packet of {stream['count']}")

            # Отправка подтверждения о получении пакета
            self.send_acknowledgment(data)

            if stream["count"] == len(stream["packets"]):

                self.logger.info(f"all packets for this stream have been received!")

                data = bytes()
                for chunk_id in sorted(stream["packets"]):
                    data += stream["packets"][chunk_id]

                # Поток собран: освобождаем его id, иначе следующий поток с тем же
                # id (счётчик идёт по кругу в пределах байта) допишется к этому
                del self.WAITING_STREAMS[packet.stream_id]

                # Передаем выше
                self.UPPER_LEVEL.receive(data)


    # постоянно читает PENDING_SEND_BUF, формирует пакет и отправляет данные ниже
    def sworker(self, data):

        chunks = [data[i:i + self.CHUNK_SIZE] for i in range(0, len(data), self.CHUNK_SIZE)]
        self.logger.info(f"divided data into chunks: count: {len(chunks)}")

        for n, chunk in enumerate(chunks):

            self.logger.info(f"start sending chunk {n}")

            packet = TransportPacket(0x0, self.CURRENT_STREAM_ID, len(chunks), n, int(time.time()), chunk)
            raw_packet_bytes = packet.to_bytes()

            hasher = hashlib.sha256()
            hasher.update(raw_packet_bytes)
            packet_hash = hasher.hexdigest()

            self.send_with_pending_acknowledgment(raw_packet_bytes, packet_hash)
            self.logger.info(f"chunk sent!")

        self.CURRENT_STREAM_ID = (self.CURRENT_STREAM_ID + 1) % 256



