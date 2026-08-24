import threading
import time
import hashlib

from concurrent.futures import ThreadPoolExecutor

from levels.packet import TransportPacket
from levels.base import Base


class Transport(Base):

    # Сколько ждать подтверждения перед повторной отправкой и сколько попыток всего.
    # 6 x 5s держит прежний бюджет ~30s, но без бесконечной рекурсии
    ACK_TIMEOUT = 5
    ACK_RETRIES = 6

    # Сколько хешей уже обработанных пакетов помнить, чтобы отличить повтор
    # от нового пакета. Должно перекрывать окно повторов ACK_TIMEOUT * ACK_RETRIES
    SEEN_PACKETS_WINDOW = 512

    # Сколько чанков одного потока держать в полёте одновременно
    SEND_WINDOW = 8


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

        # Хеши уже собранных пакетов, в порядке поступления.
        # Читается и пишется только потоком receiver, поэтому без блокировки
        self.SEEN_PACKETS = {}

        # Текущий STREAM ID. Нужен для нумерации потоков байт
        self.CURRENT_STREAM_ID = 0

        # Размер чанков данных в байтах
        self.CHUNK_SIZE = 100

        # Пинг включается ядром после инициализации. До этого стек ещё не готов
        # отправлять пакеты, а само рукопожатие подтверждает, что собеседник на месте
        self.PING_ENABLED = False

        threading.Thread(target=self.every_second).start()


    # Третий поток, каждую секунду выполняющий что-либо
    def every_second(self):
        while not self.stop_event.is_set():

            # Если больше 30 секунд от собеседника не приходило ни одного пакета, то отправляем пинг
            if self.PING_ENABLED and self.TIME_SINCE_LAST_PACKET > 30:
                self.send_with_pending_ping()

            # Прибавляем единицу, чтобы понимать сколько прошло секунд с получения последнего пакета
            with self.TIME_SINCE_LAST_PACKET_LOCK:
                self.TIME_SINCE_LAST_PACKET += 1

            time.sleep(1)


    # PUBLIC функция: её вызывает ядро, когда стек полностью проинициализирован.
    # Счётчик обнуляется: рукопожатие только что прошло, собеседник точно на месте
    def enable_ping(self):

        with self.TIME_SINCE_LAST_PACKET_LOCK:
            self.TIME_SINCE_LAST_PACKET = 0

        self.PING_ENABLED = True


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

        # Event вместо опроса: поток просыпается в момент прихода подтверждения,
        # а не на следующем тике таймера
        acknowledged = threading.Event()
        with self.PENDING_ACK_PACKS_LOCK:
            self.PENDING_ACK_PACKS[packet_hash] = acknowledged

        try:
            for attempt in range(self.ACK_RETRIES):

                self.logger.info(f"send packet '{packet_hash}' (attempt {attempt + 1})")
                self.LOWER_LEVEL.send(raw_packet_bytes)

                if acknowledged.wait(self.ACK_TIMEOUT):
                    self.logger.info(f"ack received!")
                    return

                if self.stop_event.is_set():
                    return

                self.logger.warning(f"timeout while wait ack, resending")

            self.logger.error(f"giving up on '{packet_hash}' after {self.ACK_RETRIES} attempts")

        finally:
            with self.PENDING_ACK_PACKS_LOCK:
                self.PENDING_ACK_PACKS.pop(packet_hash, None)


    # Видели ли уже в точности этот пакет. Запоминает его и вытесняет самый старый
    def already_seen(self, raw_packet_bytes):

        hasher = hashlib.sha256()
        hasher.update(raw_packet_bytes)
        packet_hash = hasher.hexdigest()

        if packet_hash in self.SEEN_PACKETS:
            return True

        self.SEEN_PACKETS[packet_hash] = None
        if len(self.SEEN_PACKETS) > self.SEEN_PACKETS_WINDOW:
            del self.SEEN_PACKETS[next(iter(self.SEEN_PACKETS))]

        return False


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
                acknowledged = self.PENDING_ACK_PACKS.get(packet_hash)
            # Снимает запись сам отправитель, здесь только будим его
            if acknowledged:
                acknowledged.set()

        # Если просто пакет передачи данных
        if packet.flags == 0x0:

            self.logger.info(f"data packet")

            # Подтверждение отправляем всегда: отправитель повторяет пакет
            # именно потому, что не увидел предыдущего подтверждения
            self.send_acknowledgment(data)

            # Повтор уже собранного пакета собирать заново нельзя: одночанковый
            # поток доставился бы наверх дважды, а многочанковый склеился бы с чужим
            if self.already_seen(data):
                self.logger.info(f"duplicate packet, acknowledged and ignored")
                return

            # Чанки лежат в словаре по chunk_id: повторно присланный чанк
            # перезаписывает себя же, а не задваивает счётчик
            stream = self.WAITING_STREAMS.setdefault(
                packet.stream_id, {"count": packet.chunk_count, "packets": {}}
            )
            stream["packets"][packet.chunk_id] = packet.payload

            self.logger.info(f"stream {packet.stream_id}: {len(stream['packets'])} packet of {stream['count']}")

            if stream["count"] == len(stream["packets"]):

                self.logger.info(f"all packets for this stream have been received!")

                # Стрим удаляется сразу: иначе он копится в памяти, а после
                # оборота stream_id через 256 новые чанки дописались бы в старый
                del self.WAITING_STREAMS[packet.stream_id]

                data = b"".join(stream["packets"][chunk_id] for chunk_id in sorted(stream["packets"]))

                # Передаем выше
                self.UPPER_LEVEL.receive(data)


    # постоянно читает PENDING_SEND_BUF, формирует пакет и отправляет данные ниже
    def sworker(self, data):

        chunks = [data[i:i + self.CHUNK_SIZE] for i in range(0, len(data), self.CHUNK_SIZE)]
        self.logger.info(f"divided data into chunks: count: {len(chunks)}")

        outgoing = []
        for n, chunk in enumerate(chunks):

            packet = TransportPacket(0x0, self.CURRENT_STREAM_ID, len(chunks), n, int(time.time()), chunk)
            raw_packet_bytes = packet.to_bytes()

            hasher = hashlib.sha256()
            hasher.update(raw_packet_bytes)
            packet_hash = hasher.hexdigest()

            outgoing.append((raw_packet_bytes, packet_hash))

        # Чанки летят с перекрытием: ожидание подтверждения по очереди стоило бы
        # полного round-trip на каждый чанк. Получатель собирает поток по chunk_id,
        # поэтому порядок прибытия внутри потока значения не имеет.
        # Окно ограничено, чтобы большое сообщение не породило поток на каждый чанк
        with ThreadPoolExecutor(max_workers=self.SEND_WINDOW) as pool:
            futures = [pool.submit(self.send_with_pending_acknowledgment, raw, packet_hash)
                       for raw, packet_hash in outgoing]
            for future in futures:
                future.result()

        self.logger.info(f"all {len(chunks)} chunk(s) sent!")

        self.CURRENT_STREAM_ID = (self.CURRENT_STREAM_ID + 1) % 256


    # PUBLIC функция: её вызывает ядро.
    # Отбросить уже принятые пакеты с данными и незавершённые потоки.
    # Подтверждения и пинги не трогаем: на них завязана доставка
    def drop_pending_data(self):

        for raw_packet_bytes in self.take_pending_processing():

            try:
                packet = TransportPacket.from_bytes(raw_packet_bytes)
            except Exception as e:
                self.logger.error(e)
                continue

            if packet.flags != 0x0:
                self.PENDING_PROCESSING_BUF.put(raw_packet_bytes)

        self.WAITING_STREAMS.clear()



