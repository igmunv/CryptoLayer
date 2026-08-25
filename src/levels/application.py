import os
import threading
import time

from enum import IntEnum

from levels.packet import ApplicationPacket, PackTypes, DataTypes, CMDTypes, TextMessagePacket

from levels.base import Base


# Этапы рукопожатия.
# Служебные пакеты принимаются строго на своём этапе, всё остальное отбрасывается
class HandshakeStages(IntEnum):

    # Ждём node id собеседника
    WAIT_NODE_ID = 0

    # Ждём публичную часть подписи собеседника
    WAIT_SIGN = 1

    # Подпись собеседника получена, но пользователь ещё не подтвердил доверие к ней:
    # обязательная проверка подписей на переходном уровне ещё не включена,
    # поэтому доверять чему-либо пришедшему в этот момент нельзя
    SIGN_RECEIVED = 2

    # Проверка подписей включена, ждём ECDH-ключ собеседника
    WAIT_PUBLIC_KEY = 3

    # Рукопожатие завершено
    READY = 4


class Application(Base):


    def __init__(self):

        # Текущий этап рукопожатия.
        # Выставляется до super(), так как Base сразу запускает потоки уровня
        self.HANDSHAKE_STAGE = HandshakeStages.WAIT_NODE_ID

        # Этап меняется из потока инициализации (expect_public_key), а проверяется
        # из потока уровня (rworker), поэтому обработка пакета и смена этапа
        # не должны накладываться друг на друга
        self.HANDSHAKE_STAGE_LOCK = threading.Lock()

        # Свой ECDH-ключ. Нужен, чтобы отправить его повторно (см. handle_packet)
        self.MY_PUBLIC_KEY_BYTES = None

        super().__init__()


    def send_text(self, text: str):
        packet = ApplicationPacket(PackTypes.COMMUNIC.value, DataTypes.TEXT.value, TextMessagePacket(int(time.time()), text.encode()).to_bytes())
        self.send(packet.to_bytes())


    def send_my_node_id(self, node_id: str):
        packet = ApplicationPacket(PackTypes.SERVICE.value, CMDTypes.MY_NODE_ID.value, node_id.encode())
        self.send(packet.to_bytes())


    def send_my_sign(self, sign: bytes):
        packet = ApplicationPacket(PackTypes.SERVICE.value, CMDTypes.MY_SIGN.value, sign)
        self.send(packet.to_bytes())


    def send_my_public_key(self, public_key: bytes):
        self.MY_PUBLIC_KEY_BYTES = public_key
        packet = ApplicationPacket(PackTypes.SERVICE.value, CMDTypes.MY_PUBLIC_KEY.value, public_key)
        self.LOWER_LEVEL.send_without_encrypt(packet.to_bytes())


    def send_disconnect(self):
        packet = ApplicationPacket(PackTypes.SERVICE.value, CMDTypes.DISCONNECT.value, b'')
        self.send(packet.to_bytes())


    # PUBLIC функция: её вызывает ядро, когда подпись собеседника проверена
    # и включена обязательная проверка подписей у всех приходящих пакетов.
    # Только с этого момента можно принимать ECDH-ключ собеседника
    def expect_public_key(self):
        with self.HANDSHAKE_STAGE_LOCK:
            # Всё, что пришло до включения проверки подписей, доверия не заслуживает
            self.take_pending_processing()
            self.HANDSHAKE_STAGE = HandshakeStages.WAIT_PUBLIC_KEY


    # Проверка, что пакет пришёл на своём этапе рукопожатия
    def check_stage(self, expected_stage, packet_name):

        if self.HANDSHAKE_STAGE == expected_stage:
            return True

        self.logger.warning(f"{packet_name} packet at stage {self.HANDSHAKE_STAGE.name}: dropped")
        return False


    # постоянно читает данные из PENDING_PROCESSING_BUF и обрабатывает их и отправляет выше
    def rworker(self, data):
        with self.HANDSHAKE_STAGE_LOCK:
            self.handle_packet(data)


    def handle_packet(self, data):

        packet = ApplicationPacket.from_bytes(data)

        if packet.pack_type == PackTypes.SERVICE.value:

            if packet.data_type == CMDTypes.MY_NODE_ID.value:

                if not self.check_stage(HandshakeStages.WAIT_NODE_ID, "MY_NODE_ID"):
                    return

                # node id приходит по сети и может быть мусором
                try:
                    node_id = packet.payload.decode()
                except UnicodeDecodeError:
                    self.logger.warning("MY_NODE_ID payload is not valid utf-8: dropped")
                    return

                if not self.UPPER_LEVEL.receive_node_id(node_id):
                    return

                self.HANDSHAKE_STAGE = HandshakeStages.WAIT_SIGN

            elif packet.data_type == CMDTypes.MY_SIGN.value:

                if not self.check_stage(HandshakeStages.WAIT_SIGN, "MY_SIGN"):
                    return

                # Та же логика, что и для node id: разбор подписи может завершиться ошибкой
                if not self.UPPER_LEVEL.receive_sign(packet.payload):
                    return

                self.HANDSHAKE_STAGE = HandshakeStages.SIGN_RECEIVED

            elif packet.data_type == CMDTypes.MY_PUBLIC_KEY.value:

                if self.HANDSHAKE_STAGE != HandshakeStages.WAIT_PUBLIC_KEY:
                    # Собеседник мог прислать ключ раньше, чем мы включили проверку подписей,
                    # или повторить отправку уже после рукопожатия - такой пакет не используется
                    self.logger.info(f"MY_PUBLIC_KEY packet at stage {self.HANDSHAKE_STAGE.name}: dropped")
                    return

                # Аналогично node id и подписи: ECDH-ключ разбирается в ядре и
                # может оказаться некорректным
                if not self.UPPER_LEVEL.receive_public_key(packet.payload):
                    return

                self.HANDSHAKE_STAGE = HandshakeStages.READY

                # Наш ключ собеседник мог отбросить, если получил его до того,
                # как включил у себя проверку подписей. Отправляем ещё раз
                if self.MY_PUBLIC_KEY_BYTES is not None:
                    self.send_my_public_key(self.MY_PUBLIC_KEY_BYTES)

            elif packet.data_type == CMDTypes.DISCONNECT.value:

                if not self.check_stage(HandshakeStages.READY, "DISCONNECT"):
                    return

                self.UPPER_LEVEL.receive_disconnect()

        elif packet.pack_type == PackTypes.COMMUNIC.value:

            if not self.check_stage(HandshakeStages.READY, "COMMUNIC"):
                return

            if packet.data_type == DataTypes.TEXT.value:
                text_packet = TextMessagePacket.from_bytes(packet.payload)
                self.UPPER_LEVEL.receive_text(text_packet.time, text_packet.payload.decode())


    # постоянно читает PENDING_SEND_BUF, формирует пакет и отправляет данные ниже
    def sworker(self, data):
        self.LOWER_LEVEL.send(data)


