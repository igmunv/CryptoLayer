import threading
import sys
import time
import os
import re
import uuid
import logging

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from base_module import BaseModule

from levels.application import Application
from levels.presentation import Presentation
from levels.transport import Transport
from levels.transitional import Transitional
from levels.base import Base

import config

from UIProvider import UIProvider


# node id состоит только из шестнадцатеричных символов
NODE_ID_PATTERN = re.compile(r"\A[0-9a-f]+\Z")


class CryptoLayer:


    def __init__(self, ui_provider: UIProvider, data_dir: str, module_class: BaseModule, password: str, wordcoder_dict: dict):

        # Словарь слов для wordcoder
        self.WORDCODER_DICT = wordcoder_dict

        # UI
        self.ui_provider = ui_provider

        # Путь к директории для данных
        self.data_dir = data_dir

        # Класс модуля
        self.MODULE_CLASS = module_class

        # Пароль пользователя
        self.USER_PASSWORD = bytearray(password.encode('utf-8'))

        # Пути к файлам
        self.KNOWN_NODES_DIR_PATH = os.path.join(data_dir, config.KNOWN_NODES_DIR_NAME)
        self.NODE_ID_FILE_PATH = os.path.join(data_dir, config.NODE_ID_FILE_NAME)
        self.SIGN_PRIVATE_FILE_PATH = os.path.join(data_dir, config.SIGN_PRIVATE_FILE_NAME)
        self.LOGS_FILE_PATH = os.path.join(data_dir, config.LOGS_FILE_NAME)

        # Логирование
        self.LOGGER = logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}")

        # ID собеседника в мессенджере
        self.COMPANION_ID = None

        # ID текущего узла
        self.NODE_ID = None

        # Цифровая подпись
        # Приватный ключ
        self.SIGN_PRIVATE_KEY = None
        # Публичный ключ
        self.SIGN_PUBLIC_KEY = None

        # Приватный ключ для ECC
        self.MY_PRIVATE_KEY = None

        # Ключ шифрования AES
        self.AES_KEY = None

        # NODE ID собеседника
        self.COMPANION_NODE_ID = None

        # подпись собеседника
        self.COMPANION_SIGN = None

        # ECC public key собеседника
        self.COMPANION_PUBLIC_KEY = None

        # Выставляются при получении соответствующих данных от собеседника.
        # Ожидающий поток просыпается сразу, а не на следующем тике опроса
        self.COMPANION_NODE_ID_RECEIVED = threading.Event()
        self.COMPANION_SIGN_RECEIVED = threading.Event()
        self.COMPANION_PUBLIC_KEY_RECEIVED = threading.Event()

        # Уровни
        self.TRANSITIONAL_LEVEL = None
        self.TRANSPORT_LEVEL = None
        self.PRESENTATION_LEVEL = None
        self.APPLICATION_LEVEL = None

        # Функция принимающая данные от мессенджера
        self.TRANSITIONAL_LEVEL_INGESTER = None


    def init(self):

        # Создаем директорию с данными
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.KNOWN_NODES_DIR_PATH, exist_ok=True)

        # инциализация уровней
        self.init_levels()

        # Настройка модуля
        self.init_module()

        # Работа с подписями
        self.signatures_setup()

        # Ключи шифрования
        self.generate_and_exchange_ecc_keys()

        # удаление пароля из RAM
        self.remove_password_from_ram()

        # Стек готов: только теперь имеет смысл проверять доступность собеседника
        self.TRANSPORT_LEVEL.enable_ping()

        self.ui_provider.on_ready()


    def init_levels(self):

        self.ui_provider.update_status("Levels", "Loading...", "in_progress")

        Base.core = self

        self.APPLICATION_LEVEL = Application()
        self.PRESENTATION_LEVEL = Presentation()
        self.TRANSPORT_LEVEL = Transport()
        self.TRANSITIONAL_LEVEL = Transitional(self.WORDCODER_DICT)
        self.TRANSITIONAL_LEVEL_INGESTER = self.TRANSITIONAL_LEVEL.receive

        self.ui_provider.update_status("Levels", "Level class objects created", "in_progress")

        self.APPLICATION_LEVEL.update_levels(self, self.PRESENTATION_LEVEL)
        self.PRESENTATION_LEVEL.update_levels(self.APPLICATION_LEVEL, self.TRANSPORT_LEVEL)
        self.TRANSPORT_LEVEL.update_levels(self.PRESENTATION_LEVEL, self.TRANSITIONAL_LEVEL)

        self.ui_provider.update_status("Levels", "Done", "success")


    def init_module(self):

        self.ui_provider.update_status("Module", "Create session...", "in_progress")

        # Создаем сессию в модуле мессенджера
        self.MODULE_CLASS.create_session(self.TRANSITIONAL_LEVEL_INGESTER)
        self.TRANSITIONAL_LEVEL.update_levels(self.TRANSPORT_LEVEL, self.MODULE_CLASS.sender)

        self.ui_provider.update_status("Module", "Done", "success")


    def signatures_setup(self):

        self.ui_provider.update_status("Signatures", "Loading...", "in_progress")

        # Генерация ID узла
        self.generate_node_id()

        # Чтение или генерация цифровой подписи данного узла
        self.generate_signature()

        # Обмен ID узлов
        self.node_id_exchange()

        # Проверка существования цифровой подписи собеседника
        # Передача цифровой подписи
        # Затем спрашиваем у пользователя доверяем ли этой подписи, показывая первые 4 символа, и последние
        self.check_and_exchange_companion_sign()

        self.ui_provider.update_status("Signatures", "Done", "success")


    # Генерация или получение ID узла
    def generate_node_id(self):

        # Попытка прочитать ID

        if os.path.exists(self.NODE_ID_FILE_PATH):
            node_id_file_content = open(self.NODE_ID_FILE_PATH, encoding="utf-8").read().strip()
            if self.check_node_id(node_id_file_content):
                self.NODE_ID = node_id_file_content
                return

        # Генерация ID
        new_node_id = ""
        for i in range(2):
            random_id = uuid.uuid4()
            new_node_id += random_id.hex

        with open(self.NODE_ID_FILE_PATH, "w", encoding="utf-8") as f:
            f.write(new_node_id)

        self.NODE_ID = new_node_id


    # Генерация или получение цифровой подписи данного узла
    def generate_signature(self):

        # файл нашей подписи есть
        if os.path.exists(self.SIGN_PRIVATE_FILE_PATH):

            self.ui_provider.update_status("Signatures", "Our signature file exists", "in_progress")

            with open(self.SIGN_PRIVATE_FILE_PATH, "rb") as f:
                loaded_pem_data = f.read()

            # если файл не пустой
            if loaded_pem_data:

                self.ui_provider.update_status("Signatures", "Signature file not empty. Use this signature", "in_progress")

                self.SIGN_PRIVATE_KEY = serialization.load_pem_private_key(
                    loaded_pem_data,
                    password=bytes(self.USER_PASSWORD)
                )

                self.SIGN_PUBLIC_KEY = self.SIGN_PRIVATE_KEY.public_key()

                self.TRANSITIONAL_LEVEL.SIGN_PRIVATE_KEY = self.SIGN_PRIVATE_KEY

                return

            else:
                self.ui_provider.update_status("Signatures", "Signature file empty", "in_progress")


        # ... генерация
        self.ui_provider.update_status("Signatures", "Generate new our signature...", "in_progress")

        self.SIGN_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
        self.SIGN_PUBLIC_KEY = self.SIGN_PRIVATE_KEY.public_key()
        self.TRANSITIONAL_LEVEL.SIGN_PRIVATE_KEY = self.SIGN_PRIVATE_KEY

        # Сохранение приватного ключа в файл в зашифрованном виде

        pem_private_data = self.SIGN_PRIVATE_KEY.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(bytes(self.USER_PASSWORD))
        )

        self.ui_provider.update_status("Signatures", "Write new signature in file", "in_progress")

        # Записываем байты в файл
        with open(self.SIGN_PRIVATE_FILE_PATH, "wb") as f:
            f.write(pem_private_data)


    # Обмен ID узлов
    def node_id_exchange(self):

        # Передача друг другу Node ID
        # Ожидаем NODE ID собеседника
        self.ui_provider.update_status("Signatures", "Send node id...", "in_progress")
        self.LOGGER.info("Signatures: Send node id...")
        self.APPLICATION_LEVEL.send_my_node_id(self.NODE_ID)
        self.ui_provider.update_status("Signatures", "Waiting for companion node id...", "in_progress")
        self.LOGGER.info("Signatures: Waiting for companion node id...")
        self.COMPANION_NODE_ID_RECEIVED.wait()
        self.ui_provider.update_status("Signatures", "Companion node id received!", "in_progress")
        self.LOGGER.info("Signatures: Companion node id received!")


    # Проверка существования цифровой подписи собеседника и обмен ею
    def check_and_exchange_companion_sign(self):

        # Отправка своей подписи
        # Ожидание подписи собеседника

        try:
            self.ui_provider.update_status("Signatures", "Send signature...", "in_progress")
            self.LOGGER.info("Signatures: Send signature...")
            my_sign_public_bytes_X962 = self.get_key_bytes_X962(self.SIGN_PUBLIC_KEY)
            self.APPLICATION_LEVEL.send_my_sign(my_sign_public_bytes_X962)
            self.ui_provider.update_status("Signatures", "Waiting for companion signature...", "in_progress")
            self.LOGGER.info("Signatures: Waiting for companion signature...")
            self.COMPANION_SIGN_RECEIVED.wait()
            self.ui_provider.update_status("Signatures", "Companion signature received!", "in_progress")
            self.LOGGER.info("Signatures: Companion signature received!")

            # Затем сравнение с тем, что в файле
            COMPANION_SIGN_FILE_PATH = self.get_known_node_file_path(self.COMPANION_NODE_ID)
            if os.path.exists(COMPANION_SIGN_FILE_PATH):
                self.ui_provider.update_status("Signatures", "Сompanion signature exists", "in_progress")
                self.LOGGER.info("Signatures: Сompanion signature exists")

                # Читаем из файла подпись
                try:
                    self.ui_provider.update_status("Signatures", "Reading companion signature from file...", "in_progress")
                    self.LOGGER.info("Signatures: Reading companion signature from file...")
                    file_comp_sign_public_bytes_X962 = self.read_encrypted_file(COMPANION_SIGN_FILE_PATH, self.USER_PASSWORD)
                    comp_sign_public_bytes_X962 = self.get_key_bytes_X962(self.COMPANION_SIGN)

                    if file_comp_sign_public_bytes_X962 == comp_sign_public_bytes_X962:
                        # если похожи то идем дальше
                        # Все норм они равны. Можем переходить к следующему этапу
                        self.ui_provider.update_status("Signatures", "Companion signature exists", "in_progress")
                        self.LOGGER.info("Signatures: Companion signature exists")
                        return

                    else:
                        # не совпадают
                        pass

                except Exception as e:
                    # Если ошибка то значит будем просить пользователя проверить и перезапишем файл
                    self.ui_provider.update_status("Signatures", "Failed to read signature from file!", "in_progress")
                    self.LOGGER.info(f"Signatures: Failed to read signature from file: {e}")


            # Если код продолжается то значит что нет файла,
            # Либо в файле лежит что-то другое,
            # Либо подпись в файле не совпадает с полученной:
            # - просим пользователя проверить подпись

            self.LOGGER.info("Signatures: user signatures check...")

            # Проверка подписи собеседника пользователем
            if self.ui_provider.check_signatures(self.get_firts_last_4_chars_sign(self.SIGN_PUBLIC_KEY), self.get_firts_last_4_chars_sign(self.COMPANION_SIGN)):

                # Доверяем, записываем, используем эту подпись

                # Зашифровываем публичную подпись собеседника паролем и сохраняем в файл

                self.ui_provider.update_status("Signatures", "Save companion signature in file...", "in_progress")
                self.LOGGER.info("Signatures: Save companion signature in file...")
                comp_sign_public_bytes_X962 = self.get_key_bytes_X962(self.COMPANION_SIGN)
                self.encrypt_write_file(COMPANION_SIGN_FILE_PATH, self.USER_PASSWORD, comp_sign_public_bytes_X962)


            else:
                raise TypeError("do not trust the signature")

        finally:
            self.TRANSITIONAL_LEVEL.COMPANION_SIGN_PUBLIC_KEY = self.COMPANION_SIGN # обновляем подпись собеседника
            self.TRANSITIONAL_LEVEL.DO_SIGN = True # ОБЯЗАТЕЛЬНО!!! Так как теперь используется подпись


    # Генерация и обмен публичными ключами, вычисление симметриного ключа
    def generate_and_exchange_ecc_keys(self):

        # Генерация пары ключей
        self.ui_provider.update_status("Encryption", "Generate keys...", "in_progress")
        self.LOGGER.info("Encryption: Generate keys...")
        self.MY_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
        my_public_key = self.MY_PRIVATE_KEY.public_key()
        my_pkey_bytes = my_public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint
            )

        # Всё, что пришло до включения обязательной проверки подписей, могло быть
        # отправлено кем угодно. Отбрасываем такие данные и только после этого
        # разрешаем приём ECDH-ключа собеседника
        self.drop_unauthenticated_data()

        # Передача публичного ключа
        # Ожидаем публичный ключ от собеседника
        self.ui_provider.update_status("Encryption", "Send public key...", "in_progress")
        self.LOGGER.info("Encryption: Send public key...")
        self.APPLICATION_LEVEL.send_my_public_key(my_pkey_bytes)

        self.ui_provider.update_status("Encryption", "Waiting for companion public key...", "in_progress")
        self.LOGGER.info("Encryption: Waiting for companion public key...")
        self.COMPANION_PUBLIC_KEY_RECEIVED.wait()

        self.ui_provider.update_status("Encryption", "Companion public key received!", "in_progress")
        self.LOGGER.info("Encryption: Companion public key received!")

        # Вычисление симетричного ключа
        self.ui_provider.update_status("Encryption", "Symmetric key computation...", "in_progress")
        self.LOGGER.info("Encryption: Symmetric key computation...")
        self.AES_KEY = self.MY_PRIVATE_KEY.exchange(ec.ECDH(), self.COMPANION_PUBLIC_KEY)

        self.PRESENTATION_LEVEL.DO_ENCRYPT = True
        self.PRESENTATION_LEVEL.AES_KEY = self.AES_KEY

        self.ui_provider.update_status("Encryption", "Done", "success")


    # Отбросить всё, что пришло до включения обязательной проверки подписей,
    # и разрешить приём ECDH-ключа собеседника.
    # Вызывать только после DO_SIGN = True: данные, ещё не дошедшие до переходного
    # уровня, будут проверены при обработке, поэтому чистим только то, что этот
    # уровень уже успел пропустить. Уровни чистятся снизу вверх
    def drop_unauthenticated_data(self):

        self.TRANSPORT_LEVEL.drop_pending_data()
        self.PRESENTATION_LEVEL.take_pending_processing()

        # Буфер прикладного уровня чистится внутри expect_public_key под тем же
        # замком, под которым выполняется его rworker
        self.APPLICATION_LEVEL.expect_public_key()


    # Отправка сообщения
    def send(self, text):
        self.APPLICATION_LEVEL.send_text(text)


    def receive_node_id(self, node_id: str):

        # node id собеседника приходит по сети и используется как имя файла
        # в known_nodes, поэтому принимается только node id ожидаемого вида
        if not self.check_node_id(node_id):
            self.LOGGER.error("companion node id is not valid: dropped")
            return

        self.COMPANION_NODE_ID = node_id
        self.COMPANION_NODE_ID_RECEIVED.set()


    def receive_sign(self, sign: bytes):
        self.COMPANION_SIGN = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            sign
        )
        self.COMPANION_SIGN_RECEIVED.set()


    def receive_public_key(self, public_key: bytes):
        self.COMPANION_PUBLIC_KEY = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            public_key
        )
        self.COMPANION_PUBLIC_KEY_RECEIVED.set()


    def receive_text(self, timestamp: int, text: str):
        self.ui_provider.on_text_received(timestamp, text)


    def receive_disconnect(self):
        self.ui_provider.on_disconnect()


    def encrypt_write_file(self, filename, password, data):
        salt = os.urandom(16)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"public-key-encryption",
        )
        up_aes_key = hkdf.derive(password)

        aesgcm = AESGCM(up_aes_key)
        nonce = os.urandom(12)
        encrypted_data = aesgcm.encrypt(nonce, data, associated_data=None)

        with open(filename, "wb") as f:
            f.write(salt + nonce + encrypted_data)


    def read_encrypted_file(self, filename, password):
        with open(filename, "rb") as f:
            file_content = f.read()
        return self.decrypt_data_AES(file_content, password)


    def decrypt_data_AES(self, data, password):

        salt = data[:16]
        nonce = data[16:28]
        encrypted_data = data[28:]

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"public-key-encryption",
        )
        up_aes_key = hkdf.derive(password)

        aesgcm = AESGCM(up_aes_key)
        return aesgcm.decrypt(nonce, encrypted_data, associated_data=None)


    # Проверка, что node id имеет ожидаемый вид: два uuid4 в шестнадцатеричном виде
    def check_node_id(self, node_id: str) -> bool:
        return len(node_id) == config.NODE_ID_LENGTH and NODE_ID_PATTERN.match(node_id) is not None


    # Путь к файлу с подписью узла внутри known_nodes.
    # Дополнительная проверка на случай, если сюда попадёт непроверенный node id
    def get_known_node_file_path(self, node_id: str) -> str:

        file_path = os.path.join(self.KNOWN_NODES_DIR_PATH, node_id)

        if os.path.dirname(os.path.realpath(file_path)) != os.path.realpath(self.KNOWN_NODES_DIR_PATH):
            raise ValueError("node id points outside the known_nodes directory")

        return file_path


    def load_key_from_X962_bytes(self, key_bytes):
        return ec.EllipticCurvePublicKey.from_encoded_point(
            curve=ec.SECP256R1(),
            data=key_bytes
        )


    def get_key_bytes_X962(self, key):
        return key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )


    # Удалить мастер пароль из памяти
    def remove_password_from_ram(self):
        for i in range(len(self.USER_PASSWORD)):
            self.USER_PASSWORD[i] = 0


    # Получить первые и последние 4 байта подписи
    def get_firts_last_4_chars_sign(self, sign):

        sign_public_bytes_pem = sign.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )

        first_4 = sign_public_bytes_pem[:4]
        last_4 = sign_public_bytes_pem[-4:]
        return f"{first_4.hex()}...{last_4.hex()}"



    # Остановить работу CryptoLayer
    def stop(self, send_disconnect=True):

        self.ui_provider.update_status("CryptoLayer", "Shutting down...", "in_progress")

        if send_disconnect:
            self.APPLICATION_LEVEL.send_disconnect()
            time.sleep(1)

        # Ожидаем отправления всех пакетов
        timeout = 30
        levels = (self.APPLICATION_LEVEL, self.PRESENTATION_LEVEL, self.TRANSPORT_LEVEL, self.TRANSITIONAL_LEVEL)
        while self.TRANSPORT_LEVEL.PENDING_ACK_PACKS or any(level.PENDING_SEND_BUF.qsize() for level in levels):

            if timeout <= 0:
                break

            timeout -= 1
            time.sleep(1)


        Base.stop_event.set()
        BaseModule.stop_event.set()

        self.ui_provider.update_status("CryptoLayer", "Bye!", "success")


    # Таймаут при пинге
    def on_ping_timeout(self):
        self.ui_provider.on_ping_timeout()

