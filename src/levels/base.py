import queue
import threading
import logging


class Base:

    stop_event = threading.Event()

    # Здесь класс CryptoLayer. Это нужно для обратной связи от уровней
    core = None

    # Как долго рабочий поток ждёт данные, прежде чем перепроверить stop_event.
    # На задержку доставки не влияет: Queue будит поток сразу при put().
    POLL_TIMEOUT = 0.1

    def __init__(self):

        # Буффер пришедших данных
        self.PENDING_PROCESSING_BUF = queue.Queue()

        # Буффер готовых к передаче данных
        self.PENDING_SEND_BUF = queue.Queue()


        self.logger = logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}")


        # запуск 2-х потоков:
        # первый Receiver - читает что в буффере пришло от transitional
        # второй Sender - читает что нужно отправить
        threading.Thread(target=self.sender).start()
        threading.Thread(target=self.receiver).start()


    # Обновить уровни: нижестоящий и вышестоящий
    def update_levels(self, upper_level, lower_level):
        # Класс-Уровень выше
        self.UPPER_LEVEL = upper_level
        # Класс-Уровень ниже
        self.LOWER_LEVEL = lower_level


    # PUBLIC фунция: её вызывает верхний уровень: отправь эти данные
    def send(self, data):
        self.logger.info(f"size: {len(data)}")
        self.PENDING_SEND_BUF.put(data)


    # PUBLIC фунция: её вызывает нижний уровень: получай эти данные
    def receive(self, data):
        self.logger.info(f"size: {len(data)}")
        self.PENDING_PROCESSING_BUF.put(data)


    # PUBLIC функция: забрать всё, что сейчас лежит в буффере приёма.
    # Нужна, чтобы отбросить данные, пришедшие до того, как собеседник был проверен
    def take_pending_processing(self):

        taken = []

        while True:
            try:
                taken.append(self.PENDING_PROCESSING_BUF.get_nowait())
            except queue.Empty:
                return taken


    # Отдаёт рабочей функции всё, что попадает в буффер, пока не выставлен stop_event.
    # Обработчик вызывается вне блокировки буффера: transport ждёт подтверждения
    # секундами, и держать буффер занятым всё это время значит застопорить уровни выше.
    def _pump(self, buffer, worker):
        while not self.stop_event.is_set():
            try:
                data = buffer.get(timeout=self.POLL_TIMEOUT)
            except queue.Empty:
                continue
            self.logger.info(f"size: {len(data)}")
            try:
                worker(data)
            except Exception:
                # Иначе исключение убивает поток и уровень молча замолкает навсегда
                self.logger.exception("worker failed, data dropped")


    # постоянно читает данные из PENDING_PROCESSING_BUF
    def receiver(self):
        self._pump(self.PENDING_PROCESSING_BUF, self.rworker)


    # обрабатывает данные и отправляет выше
    def rworker(self, data):
        pass


    # постоянно читает PENDING_SEND_BUF
    def sender(self):
        self._pump(self.PENDING_SEND_BUF, self.sworker)


    # формирует пакет и отправляет данные ниже
    def sworker(self, data):
        pass
