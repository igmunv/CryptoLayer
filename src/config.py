

# Имена файлов и директорий
KNOWN_NODES_DIR_NAME = "known_nodes/"
NODE_ID_FILE_NAME = "node_id"
SIGN_PRIVATE_FILE_NAME = "sign_private"
LOGS_FILE_NAME = "crypto_layer.log"


# Длина node id: два uuid4 в шестнадцатеричном виде
NODE_ID_LENGTH = 64


# Размер чанка (в байтах) на транспортном уровне
CHUNK_SIZE = 150

# Качество сжатия
COMPRESS_QUALITY = 11


# Ограничение на время ожидания шага рукопожатия (в секундах).
HANDSHAKE_TIMEOUT = 60

# Ограничение для шага, который ждёт действия человека (в секундах).
HANDSHAKE_USER_CHECK_TIMEOUT = 900
