<div align="center">

<img src="docs/images/logo.svg" width="250" alt="CryptoLayer Logo">

<br>
<h3>CryptoLayer</h3>
<h6>A cryptographic layer that operates on top of existing messengers, providing end-to-end message encryption solely on the user's side</h6>

[![License](https://img.shields.io/badge/License-MIT-brightgreen?color=orange&style=flat-square)](LICENSE)
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)
<br>
[![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54&style=flat-square)](https://www.python.org/)
<br>
<br>
[Русский](README.md) • English

</div>


## What is CryptoLayer?

**CryptoLayer** is a library that does not replace messengers but protects the content of your messages using cryptography.

<br>
<div align="center">
<img src="docs/diagrams/how-it-works-small-EN.png" width="750" alt="How CryptoLayer Works">
</div>
<br>

Simply put: for CryptoLayer, any messenger is **just an untrusted "wire"**, so all encryption and delivery guarantees happen exclusively within CryptoLayer **only on your device**.

<br>
<div align="center">
<img src="docs/diagrams/how-looks-data-transfer-EN.png" width="750" alt="How Looks Data Transfer">
</div>
<br>

## Custom Pseudo-Network Stack

The library implements its own pseudo-network stack:

<br>
<div align="center">
<img src="docs/diagrams/net-levels-EN.png" width="750" alt="Net Levels">
</div>
<br>

## Full Modularity

The main feature of CryptoLayer is its modularity! The communication channel can be anything:

- **Messengers**: Telegram, VK, Discord...
- **Network protocols**: HTTP, SSH, FTP, UDP...
- **Clouds and services**: Google Drive, Yandex Disk, YouTube comments, streaming platforms...
- **And other types**: clipboard, file system, Bluetooth...

### Anything! [Just write a module!](docs/README.md#5-модули)

The library **doesn't care** how bytes are transmitted. For it, **any** messenger, protocol, or service is simply an **untrusted "wire"**.

## Technology and Security

CryptoLayer uses proven technologies and methods to ensure the security of your data:

- **Encryption** - AES-256-GCM for content protection
- **Digital signatures and integrity verification** - ECDSA (SECP256R1 curve) for data signing
- **Key exchange** - ECDH protocol (SECP256R1 curve, X9.62 compressed point format)
- **Obfuscation** - custom byte-to-word encoding (WordCoder) to bypass basic messenger filters

## Ecosystem and Ready-made Applications

* **[CryptoLayer CLI](https://github.com/igmunv/cryptolayer-cli)** — official command-line interface. Great for terminal use.

* **[CryptoLayer Web UI](https://github.com/DaPon4ik/cryptolayer-webui)** — web interface for secure message exchange in messengers. Convenient and beautiful UI.

* **[zkgram](https://github.com/Gerate-Technik/zkgram)** — private Telegram client. Suitable if you need convenient and secure communication exclusively in Telegram.

> [!NOTE]
> **Want to add your project?**
> 
> If you have developed an application using **CryptoLayer**, we will be happy to add it to this list! Simply create a Pull Request with the project name, a brief description, and a link to the repository.

## Documentation

In the [documentation](docs/README.md) you will find more information about CryptoLayer:

- **How the library works**
- **How to use it** in your code
- **Architecture** of CryptoLayer

## IMPORTANT

The user has a fundamental right to **private and secure communication**. This includes the right to **independently use cryptographic means** to protect their messages, as well as the right to confidentiality of correspondence **without unauthorized access by third parties**.

The project proceeds from the principle that secure and private communication is a **basic digital norm, not a privilege**.
