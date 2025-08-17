# Alpha Steganography

A simple GUI tool for hiding and extracting encrypted messages in images. Supports both Persian and English text.

---

## Features

- Hide messages inside images using **steganography**.
- Encrypt messages with a password using **Fernet (symmetric encryption)**.
- Extract hidden messages from images using the correct password.
- Cross-platform GUI using **Tkinter**.
- Works with common image formats (PNG, JPG, etc.).
- Zenity file selection for Linux (select files and save paths easily).

---

## Requirements

- Python 3.x
- Packages:
  - `tkinter`
  - `Pillow`
  - `cryptography`
  - `base64` (built-in)
- Linux system (tested with Ubuntu)
- `zenity` installed for file dialogs:

```bash
sudo apt install zenity
```

---

## Usage

### Run via Python

1. Clone the repository:

```bash
git clone https://github.com/Mr-101a/Steganography.git
cd Steganography
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the program:

```bash
python alpha_steganography.py
```

### Run as Executable

If you use **binary**, just run:

```bash
./Alpha_Steganography
```

---

## How it works

1. **Hide a message**:

   - Select an input image.
   - Choose the output save path.
   - Enter your secret message.
   - set a password.
   - Click "Hide message".

2. **Reveal a message**:

   - Select the image containing the hidden message.
   - Enter the password used to encrypt it.
   - Click "Message Extraction".

---

## Notes

- The message size must fit within the image pixels.
- Make sure the password is the same when hiding and revealing messages.
- Works on Linux. For Windows, file selection dialogs might need adjustment.

---

**Author:** Mr.101
