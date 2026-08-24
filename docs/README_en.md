# Documentation

[Русский](README.md) • English

## Table of Contents

- [1. About CryptoLayer](#1-about-cryptolayer)
    - [1.1. What is it](#11-what-is-it)
    - [1.2. Why is it needed](#12-why-is-it-needed)
    - [1.3. Architecture](#13-architecture)
- [2. Usage](#2-usage)
    - [2.1. Integration Guide](#21-integration-guide)
    - [2.2. Basic Operations](#22-basic-operations)
    - [2.3. UIProvider](#23-uiprovider)
- [3. How it works](#3-how-it-works)
    - [3.1. Brief Steps](#31-brief-steps)
    - [3.2. Initialization](#32-initialization)
    - [3.3. Main Workflow](#33-main-workflow)
    - [3.4. Shutdown](#34-shutdown)
    - [3.5. Delivery Guarantee](#35-delivery-guarantee)
    - [3.6. Connection Stability](#36-connection-stability)
    - [3.7. Packets](#37-packets)
- [4. Data Protection](#4-data-protection)
    - [4.1. Encryption of sent data](#41-encryption-of-sent-data)
    - [4.2. Encryption of CryptoLayer files](#42-encryption-of-cryptolayer-files)
    - [4.3. Digital signatures and data integrity](#43-digital-signatures-and-data-integrity)
    - [4.4. Key exchange](#44-key-exchange)
    - [4.5. Masking](#45-masking)
- [5. Modules](#5-modules)
    - [5.1. Where are existing modules located](#51-where-are-existing-modules-located)
    - [5.2. Creating your own module](#52-creating-your-own-module)
    - [5.3. Testing your own module](#53-testing-your-own-module)

## 1. About CryptoLayer

### 1.1. What is it

CryptoLayer is a library that allows you to securely exchange messages through any messenger (and not just messengers).

The library is an independent layer between the user and the messenger, which protects transmitted data using cryptographic means.

<br>
<div align="center">
<img src="diagrams/how-it-works-small-EN.png" width="750" alt="How It Works">
</div>
<br>

### 1.2. Why is it needed

In today's world, it's difficult to 100% trust existing messengers. There is no guarantee that your data will not be passed on to third parties or used by the messenger owners.

You might immediately think about creating your own mega-secure messenger, but it could simply be blocked or forced to hand over user messages. That's why CryptoLayer **uses existing messengers**, and it uses them **simply as a communication line** (a wire) which is not trusted.

<br>
<div align="center">
<img src="diagrams/how-looks-data-transfer-EN.png" width="750" alt="How Looks Data Transfer">
</div>
<br>

### 1.3. Architecture

The library consists of three main parts: **Manager**, **pseudo-network layers**, and **modules**.

<br>
<div align="center">
<img src="diagrams/arch-EN.png" width="750" alt="Architecture">
</div>
<br>

#### Manager

Manages all the logic, as well as the pseudo-network layers. Performs initial setup and initialization of the library. Responsible for communication with the UI.

#### Pseudo-network layers

<br>
<div align="center">
<img src="diagrams/net-levels-EN.png" width="750" alt="Net Levels">
</div>
<br>

Analogous to the TCP/IP model. Each layer performs its specific function and then passes the data to the next layer:

- **Application Layer** - provides convenient functions to the manager, such as sending a text message. Packages everything into an application packet with necessary fields for convenient data handling at this layer.
- **Presentation Layer** - compresses data for more efficient transmission. Also encrypts data before sending and decrypts it after receiving.
- **Transport Layer** - provides guaranteed data delivery by splitting it into chunks, packaging a chunk into a transport packet, and then sending the packet while waiting for an acknowledgment of receipt.
- **Transition Layer** - signs outgoing data and verifies the signature of incoming data. Also, before sending to the module, it encodes data bytes into words, based on the principle 1 byte = 1 word - to mask the transmission of bytes.

#### Modules

Implement the interface for interacting with a specific data transmission channel - messenger, service, or protocol.

This is where sending and receiving data happens, by accessing the API of a specific messenger or other communication channel.

You can use anything as a data transmission channel: network protocols (http, ssh, ftp, tcp, udp), services (cloud drives, streaming platforms), messengers, file systems - **anything!** The main thing is to write a module.

Modularity allows using CryptoLayer with any messengers, protocols, and services. The main thing is that a module exists for the specific data transmission channel. If it doesn't exist, it can always be developed.

## 2. Usage

### 2.1. Integration Guide

#### 1. Add CryptoLayer to the project:

Add the library to the project as a Git submodule:

```bash
git submodule add https://github.com/igmunv/cryptolayer cryptolayer

git add .gitmodules cryptolayer/

git commit -m "Add new submodule: cryptolayer"
```

OR, if you don't want to deal with Git, download the latest version of the library:

https://github.com/igmunv/cryptolayer/releases/latest

and then unpack it into the project directory.

#### 2. Add CryptoLayer modules to the project

Do pretty much the same as in the previous step. Add the CryptoLayer modules repository to the project as a Git submodule:

```bash
git submodule add https://github.com/igmunv/cryptolayer-modules modules

git add .gitmodules modules/

git commit -m "Add new submodule: cryptolayer-modules"
```

OR, if you don't want to deal with Git, download the repository.

If you will use a different collection of modules, simply replace the URL.

#### 3. Add the library to the project configuration files:

At the end of the `requirements.txt` file, or if using `pyproject.toml`, in the `dependencies` list field, add the following dependencies:

```
-e ./cryptolayer
cryptolayer-module-interface @ git+https://github.com/igmunv/cryptolayer-module-interface.git
```

Here we added CryptoLayer as a Python library, as well as `cryptolayer-module-interface` for working with modules.

#### 4. Import libraries in code:

Import the libraries added in the previous step into your code:

```python
from crypto_layer import CryptoLayer
from UIProvider import UIProvider
from base_module import BaseModule
```

Also, it's worth importing the modules right away (it's normal that the hidden_imports.py file doesn't exist yet):

```python
import modules.hidden_imports
```

#### 5. Implementing UIProvider:

Before creating an instance of the `CryptoLayer` class, you need to implement the `UIProvider` class, which acts as an intermediary between CryptoLayer and your application with UI.

The `UIProvider` class is located in the `UIProvider.py` file in the CryptoLayer directory.

#### 6. Module:

Before creating an instance of the `CryptoLayer` class, you need to select a module, which is then passed as an argument when creating the `CryptoLayer` class.

You need to implement a module selection by the user, or statically use one specific module.

Discovering all modules can be done as follows:

```python
# Path to the submodule directory with modules
MODULES_DIR_PATH = "modules"

# Iterate over all elements in the directory
for item in os.listdir(modules_path):

    # Get the full correct path of the element
    item_path = os.path.join(MODULES_DIR_PATH, item)

    # Check if it's a directory (since the module is in a directory)
    # And that the path doesn't start with '_' (to exclude certain directories)
    if os.path.isdir(item_path) and not item.startswith('_'):

        try:

            # Try to import the module
            module = importlib.import_module(f"{item}.main")

            # Iterate over all objects in the imported module
            for name, obj in inspect.getmembers(module, inspect.isclass):

                # Look for an object inherited from BaseModule, but excluding BaseModule itself
                if issubclass(obj, BaseModule) and obj is not BaseModule:

                    # Get the module class
                    module_class = obj()

                    # We can add the module to the common list of modules
                    MODULES.append(module_class)
```

After this, the modules in the `MODULES` variable can be used, for example, for the user to select a specific module.

Each module has `name` and `description` fields, which can be listed for the user to choose a specific module. Modules also have a `unique_id` field, which is a unique module identifier. This field can be used, for example, to save some information about a specific module to a file.

#### 7. Byte-Word dictionary for WordCoder:

You need to prepare a dictionary for encoding bytes into words. It's best to give the user the ability to choose dictionaries and create their own, since different users may use different programs for working with CryptoLayer, and these programs may have their own custom dictionaries.

Ready-made dictionaries are available in this repository (you can also add it to the project as a submodule and then select the desired one):

https://github.com/igmunv/cryptolayer-wordcoder-dicts

#### 8. Creating an instance of the CryptoLayer class:

Before creating, you need to prepare the following variables:

- `ui_provider` - the implemented UIProvider class. Needed for communication between the application and CryptoLayer.
- `data_dir` - the path to the data storage directory. Needed for CryptoLayer to save its data there.
- `module_class` - the module class. CryptoLayer will use it as the module.
- `password` - the password. Used when CryptoLayer saves data to a file, to encrypt the contents (if the user forgets the password, the directory at `data_dir` needs to be deleted).
- `wordcoder_dict` - the byte-word dictionary. Needed for the WordCoder component to encode bytes into words for masking.

When all variables are ready, you can create an object of the CryptoLayer class:

```python
clayer = CryptoLayer(ui_provider, data_dir, module_class, password, wordcoder_dict)
```

After creation, you need to start the CryptoLayer initialization:

```python
clayer.init()
```

And wait for CryptoLayer to be ready. When ready, the `on_ready` function in the `UIProvider` class will be called.

#### 9. Running the project:

It is necessary to run in the following order (it's convenient to combine all commands into one file, for example `run.sh`):

- Update submodules:

```bash
git submodule update --init --recursive
```

- Run the script to generate the modules' dependencies file:

```bash
python3 modules/generate_reqs.py
```

- Run the script to generate the modules' import dependencies file (especially necessary when building the project into a binary file using PyInstaller):

```bash
python3 modules/generate_hidden_imports.py
```

- Install module dependencies:

```bash
pip install -r modules/common_requirements.txt
```

- Install project dependencies:

```bash
pip install -r requirements.txt
```

or, if using `pyproject.toml`:

```bash
pip install .
```

- Run the project:

```bash
python3 main.py # or your entry point
```

### 2.2. Basic Operations

#### Sending a message:

To send a message, you need to call the `send` method and pass the string as an argument:

```python
clayer.send(user_message)
```

#### Receiving a message:

When a message is received, CryptoLayer will call the `on_text_received` function of your UIProvider and pass the message sending time, in Unix Time Stamp format, as well as the text message itself:

```python
class UIProvider:
...
def on_text_received(self, timestamp: int, text: str):
...
```

#### Ending a session / Exiting the program:

Before ending the communication session with the current interlocutor or before exiting the program, you need to stop the current instance of the CryptoLayer class using the `stop` function:

```python
clayer.stop()
```

The function will send a `DISCONNECT` packet to the interlocutor, indicating that we are exiting and ending communication, and will also stop all threads and pseudo-network layers.

If you don't want a `DISCONNECT` packet to be sent, pass `False` to the `send_disconnect` argument (this may be needed if the interlocutor is unavailable, i.e., `on_ping_timeout` was called):

```python
clayer.stop(send_disconnect=False)
```

#### Interlocutor unavailable (Ping timeout):

If CryptoLayer detects that the interlocutor is unavailable, it will call the `on_ping_timeout` function of your UIProvider:

```python
class UIProvider:
...
def on_ping_timeout(self):
...
```

### 2.3. UIProvider

The `UIProvider` class is needed for CryptoLayer to pass data to the application and its UI. This includes, for example, the current status, a new message from the interlocutor, an error signal, etc.

When creating an application based on CryptoLayer, you must implement `UIProvider`.

Let's look at each function in UIProvider that needs to be implemented:

#### `def request_data(self, prompt: str, data_type: type)`:

This function is intended for requesting data from the user. The `prompt` argument contains the text that should be displayed when requesting data, and `data_type` is the type of data the function should return. You must return data with the type specified in `data_type`.

#### `def update_status(self, stage: str, message: str, status_type: str = "in_progress")`:

This function updates the current loading and working status of CryptoLayer. `stage` contains the stage CryptoLayer is at, `message` contains more detailed information about the operation being performed, and `status_type` is the type of status. There are three status types: `in_progress`, `success`, `error`. For example, depending on the type, you could display the status in different colors. No return value is required.

#### `def on_text_received(self, timestamp: int, text: str)`:

This function is called when a new message arrives from the interlocutor. `timestamp` is the message sending time, in Unix Time Stamp format, and `text` is the text message itself. No return value is required.

#### `def check_signatures(self, my_sign: str, companion_sign: str) -> bool`:

Called for the user to verify that the signatures are correct. `my_sign` contains the user's signature, and `companion_sign` contains the interlocutor's signature. You need to ask the user if the interlocutor's signature is correct. You must return `True` if correct, `False` if not.

#### `def on_ready(self)`:

Called when CryptoLayer has finished initialization and is ready to exchange messages. No return value is required.

#### `def on_ping_timeout(self)`:

Called when the interlocutor is unavailable. CryptoLayer continues to work, and further actions depend on the application. No return value is required.

#### `def on_disconnect(self)`:

Called when the interlocutor disconnects and ends communication. CryptoLayer continues to work, and further actions depend on the application. No return value is required.

## 3. How it works

### 3.1. Brief Steps

- Initialization
    - Exchange node identifiers
    - Exchange signatures
    - Exchange public keys
    - Generate shared key
- Main Workflow
    - Sending user message
        - Message goes down through the pseudo-network stack
        - Message is sent to the module, and then to the communication channel
    - Receiving interlocutor message
        - Message arrives from the communication channel and goes to the module
        - Message goes up through the pseudo-network stack
    - Ping
        - If there were no messages from the interlocutor for 30 seconds, a PING is sent
        - If there is no response to PING within 30 seconds, the `on_ping_timeout` function is called
- Shutdown
    - Send DISCONNECT packet
    - Disable pseudo-network stack

### 3.2. Initialization

<br>
<div align="center">
<img src="diagrams/init-EN.png" width="500" alt="Initialization">
</div>
<br>

After calling the `init` function, the initialization process starts (both nodes must start the initialization process):

#### Exchange of Node IDs

An attempt is made to read the current Node ID from the `node_id` file. If the file does not exist, the identifier is generated and written to the file. Then the identifiers are exchanged. This is needed for the next step.

#### Exchange of Digital Signatures

Next, work with digital signatures begins. An attempt is made to read the current signature private key from the `sign_private` file. If the file does not exist or the data could not be decrypted, a new digital signature for this node is generated.

Then the signatures are exchanged. After that, it is checked whether the received signature of the interlocutor is known:

In the `known_nodes` directory, a search is performed for a file whose name equals the interlocutor's `node_id`. If the file exists, the data is correctly decrypted, and the signature is known, we proceed to the encryption key exchange. If the file does not exist, the data from the file could not be decrypted, or the signature in the file does not equal the current signature of the interlocutor, then it means we have not encountered this signature before, and it needs to be verified to ensure we are indeed communicating with our interlocutor.

The user should be shown their signature and the signature of the person they are trying to start communication with. Then both interlocutors must verify their keys through another communication channel (in-person meeting, phone call, some messenger). If the keys match, then it is definitely the person we want to communicate with. After successful verification, the signature will be written to a file and CryptoLayer will remember it. This means that verification will no longer be needed, unless the interlocutor changes their signature or Node ID.

**This stage is the most critical!** Especially the signature verification - it cannot be ignored or skipped! You need to approach the correctness of signature verification with utmost seriousness!

After successful signature exchange, mandatory signature verification is activated for all incoming packets. Packets with invalid signatures will be discarded and ignored. Now you can be sure that packets are sent by your interlocutor, the person you want to communicate with. **The digital signature solves the MITM problem**, and now you can safely transmit public keys!

#### Exchange of Encryption Keys

On both nodes, an ECC public key is generated. Then the nodes exchange keys (remember, now all packets are signed, and MITM cannot be performed) and calculate a shared secret, which is used to encrypt data using AES.

Initialization completed successfully! Now the interlocutors can exchange messages **MAXIMUM SECURELY!**

### 3.3. Main Workflow

When sending, the message passes through this pipeline. I see no point in describing it in detail; everything is perfectly clear in the image:

<br>
<div align="center">
<img src="diagrams/message-transmission-chain-EN.png" width="750" alt="ACK Receive Packet">
</div>
<br>

Also during operation, CryptoLayer checks the availability of the interlocutor: if no packets have been received from the interlocutor for 30 seconds, a Ping packet is sent at the transport layer. If the interlocutor does not respond within 30 seconds, the `on_ping_timeout` function is called, after which CryptoLayer continues to work, and further actions are left to the application using CryptoLayer.

### 3.4. Shutdown

When finishing work with the current instance of the CryptoLayer class, call the `stop` function. After the call, a `DISCONNECT` packet is sent to the interlocutor, indicating that we are disconnecting and ending the conversation (the current session). Then CryptoLayer waits for ALL messages in the queue to be sent, and after that, all pseudo-network layers are disconnected.

### 3.5. Delivery Guarantee

CryptoLayer has a packet delivery guarantee mechanism (analogous to TCP). This mechanism is implemented at the transport layer of the pseudo-network stack.

<br>
<div align="center">
<img src="diagrams/ack-receive-packet-EN.png" width="750" alt="ACK Receive Packet">
</div>
<br>

After sending a packet, the sender does not send anything else until it receives an acknowledgment of receipt for the sent packet. After receiving the packet, the receiver calculates its hash and sends a special acknowledgment packet containing the hash of the received packet. The sender receives this acknowledgment packet, verifies the hash, and if everything is correct, proceeds to send the next packet. If the hash is incorrect, the packet is sent again. Or if after 30 seconds the receiver has not sent an acknowledgment packet, the sender sends the packet again and the waiting cycle resumes.

### 3.6. Connection Stability

#### Ping

If no packets have been received from the interlocutor for 30 seconds, a PING packet (transport layer) is sent to check the interlocutor's availability. The interlocutor receives the PING packet and responds to it. If there is no response from the interlocutor within 30 seconds after sending PING, the `on_ping_timeout` function is called, but CryptoLayer continues to work.

#### DISCONNECT

When exiting the program or ending the current communication session, the `stop` function is called, during which a DISCONNECT packet is sent to the interlocutor, indicating the end of the current communication session. After receiving such a packet, the interlocutor's CryptoLayer will call the `on_disconnect` function of the UIProvider. In the implementation of this function, you need to finish working with the current instance of CryptoLayer.

### 3.7. Packets

CryptoLayer implements its own pseudo-network stack. And each pseudo-network layer has its own packet with a specific structure:

<br>
<div align="center">
<img src="diagrams/packet-structures-EN.png" width="750" alt="Packet Structures">
</div>
<br>

## 4. Data Protection

### 4.1. Encryption of sent data

For encrypting data sent at the presentation pseudo-network layer, the **AES-256-GCM** algorithm is used.

### 4.2. Encryption of CryptoLayer files

CryptoLayer saves data to a file (signatures, known interlocutors). To secure this data, encryption is used, specifically the same **AES-256-GCM** algorithm, using the password that is passed as an argument when creating an instance of the CryptoLayer class.

Encrypting file contents protects against local access to these files, for example, protecting against hidden substitution of digital signatures of already known interlocutors.

### 4.3. Digital signatures and data integrity

For digital signing of packets, ECDSA (curve SECP256R1) is used.

**The digital signature solves the MITM problem!**

### 4.4. Key exchange

For exchanging public keys, the ECDH protocol (curve SECP256R1) is used. Public keys are transmitted in the compressed X9.62 point format (for maximum efficient transmission over the communication channel).

### 4.5. Masking

To mask the transmission of bytes over the communication channel (messenger primarily), each byte is replaced with a specific word: before transmitting data to the module, each byte is replaced by a word from the dictionary. As a result, from a set of bytes `0x12 0x2 0x3f 0x4`, you get text `прямо лес пружина бег` (e.g., 'straight forest spring run'). This is done by the WordCoder component.

## 5. Modules

### 5.1. Where are existing modules located

The official collection of ready-made modules for CryptoLayer is located [in this repository](https://github.com/igmunv/cryptolayer-modules).

The collection is needed for using modules from it in applications that will use CryptoLayer.

Your module can also be included there, just send a Pull Request and we will gladly accept it.

### 5.2. Creating your own module

#### 1. Preparation

In a separate directory, create the files `main.py`, `requirements.txt`, `README.md`.

In `requirements.txt`, you must specify all dependencies that the module uses.

In `README.md`, provide a description of the module, what communication channel it uses, how it works, etc.

#### 2. Import base_module

In `main.py`, you need to import the library with the base class for modules:

```python
from base_module import BaseModule, Credential
```

The `base_module` library is located [in this repository](https://github.com/igmunv/cryptolayer-module-interface).

Don't worry if this library is not in your module's directory. When using CryptoLayer, application developers will add the necessary import dependencies and everything will work correctly.

#### 3. Create a subclass of BaseModule

Now you need to create a class that inherits from `BaseModule`:

```python
...
class Example(BaseModule):
...
```

#### 4. Required fields of BaseModule

Then, you need to implement the required fields: `name` (module name), `description` (module description), `unique_id` (unique module identifier):

```python
class Example(BaseModule):
...
@property
def unique_id(self): return "ex.ample_1234"

@property
def name(self): return "Example"

@property
def description(self): return "Description for example"
...
```

#### 5. Login/Authorization Data (Credentials)

Next, you need to specify the login/authorization data (Credentials). This may be needed, for example, if you are writing a module for a messenger or other service where authorization is required. This field can also be used to input other data, not just login details: port, IP address, keys, etc. - there are no limits.

The login data will be requested by the application using CryptoLayer.

To specify login data, the `expected_credentials` field is used - an array that must contain instances of the `Credential` class. The first constructor argument is the name, the second is a description of this data. As an example, we will ask the user to enter a login and password:

```python
class Example(BaseModule):
...
expected_credentials = [Credential("Login", "User name, phone or email"), Credential("Password", "Password")]
...
```

If login data is not required, simply ignore the `expected_credentials` field.

#### 6. Nested class Sender

Next, you need to implement the nested Sender class, which is responsible for sending messages to the interlocutor's communication channel, specifically the send function, which is called by the transition pseudo-network layer of CryptoLayer. You don't need to change the function arguments; just implement sending the `text` argument to your communication channel.

The `user_id` argument of the `__init__` function passes the user identifier in the communication channel. If an identifier is not required, do not use this field.

The `credentials` argument of the `__init__` function passes the authorization data. They are in the same order as in the `expected_credentials` variable, but already in string format (list[str]).

#### 7. Nested class Listener

You also need to implement the second nested class Listener, which is responsible for receiving messages from the communication channel from the interlocutor, specifically the listen function, which should receive data from the interlocutor, and then must call the function located in the `ingester` field to pass the data up to the transition pseudo-network layer of CryptoLayer.

```python
class Example(BaseModule):
...
    class Listener:
        ...
        def listen(self) -> str:
            ...
            self.ingester(received_data) # Required, to pass data upwards
            ...
...
```

The `user_id` argument of the `__init__` function passes the user identifier in the communication channel. If an identifier is not required, do not use this field.

The `credentials` argument of the `__init__` function passes the authorization data. They are in the same order as in the `expected_credentials` variable, but already in string format (list[str]).

#### 8. Function create_session

The `create_session` function is called during CryptoLayer initialization (call to the `init` function). It is intended to create a session. In this function, instances of Sender and Listener are created, and dependencies for working with the communication channel are initialized (e.g., creating a session in the messenger).

The `create_session` function takes one argument: `ingester` - a function is passed in this argument, which then must be passed to the Listener when creating an instance.

You can override `__init__` for Sender and Listener if you need to pass other variables. The main thing is to pass `ingester` to the Listener, as without it, data will not be passed to CryptoLayer.

### 5.3. Testing your own module

To test your module, you can use [CryptoLayer CLI](https://github.com/igmunv/cryptolayer-cli).

Download the contents of the [CryptoLayer CLI](https://github.com/igmunv/cryptolayer-cli) repository.

Then run the program once using `./run.sh` or following the instructions in the [README.md](https://github.com/igmunv/cryptolayer-cli/blob/main/README.md).

After that, exit the program.

Copy your module's directory to `src/modules/`.

Next, run CryptoLayer CLI, **BUT NOT via `./run.sh`, but as follows**:

```bash
python3 -m venv venv
source venv/bin/activate
python3 src/modules/generate_reqs.py # Generate the list of module dependencies, including your new module
pip install -r src/modules/common_requirements.txt # Install module dependencies
python3 src/cryptolayer_cli.py
```

Your module will appear in CryptoLayer CLI, and now you can test it.

If you need to change the module code, you can do it directly in `src/modules/`.

**Just don't run `./run.sh` or the command `git submodule update --init --recursive` after copying the module to `src/modules/`, as this will delete your module!**

After successful testing, you can send the module to [the official repository where CryptoLayer modules are collected](https://github.com/igmunv/cryptolayer-modules)!
