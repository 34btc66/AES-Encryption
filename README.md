## AES-Encryption App [developed by 0xeop]

### Description

The AES-Encryption App is a secure and versatile tool designed for encrypting and decrypting text, files, and notes with advanced AES encryption. It also includes features like multi-key encryption, QR code generation for encrypted data, and a notepad with secure note editing capabilities.

### Key Features

- **Text Encryption/Decryption**: Securely encrypt and decrypt text using custom or generated keys.
- **File Encryption/Decryption**: Upload and encrypt/decrypt files with ease, bundled in zip format.
- **Multi-Key Encryption**: Use multiple keys for layered encryption, enhancing security.
- **QR Code Generation**: Generate QR codes for encrypted data and import them for decryption.
- **Secure Notepad**: Create, open, and edit encrypted notes with unique keys.

### Getting Started

Follow this guide to set up and run the AES-Encryption App on your local system.

---

### Prerequisites

Before you begin, ensure you have the following installed on your computer:

1. **Python 3.10 or Above**: Download and install from [python.org](https://www.python.org/downloads/). Make sure to check the box to add Python to PATH during installation.
2. **Git**: Required to clone the repository. Download from [git-scm.com](https://git-scm.com/downloads).

### Installation Guide

1. **Clone the Repository**

   Clone the project repository from GitHub:

   ```bash
   git clone https://github.com/34btc66/AES-Encryption.git
   ```

   Replace `34btc66` with your GitHub username.

2. **Navigate to the Project Directory**

   Change to the project directory:

   ```bash
   cd AES-Encryption
   ```

3. **Set Up a Virtual Environment**

   Create a virtual environment to isolate project dependencies:

   ```bash
   # Create a virtual environment
   python -m venv .venv

   # Activate the virtual environment
   # On Windows
   .venv\Scripts\activate

   # On macOS/Linux
   source .venv/bin/activate
   ```

   You should see your terminal prompt change, indicating the virtual environment is active.

4. **Install Dependencies**

   Install all required packages listed in the `requirements.txt` file:

   ```bash
   pip install -r requirements.txt
   ```

5. **Run the Application**

   Start the app using Flask:

   ```bash
   flask run
   ```

   The app will start, and you can access it at `http://127.0.0.1:5050/` in your web browser.

### Using the Application

1. **Accessing the App**: Open your browser and navigate to `http://127.0.0.1:5050/`.
2. **Creating and Managing Notes**: Use the navigation links to create new notes or open existing encrypted notes.
3. **Encrypting/Decrypting Text and Files**: Use the respective sections to encrypt or decrypt data with your specified key.
4. **QR Code Features**: Generate QR codes for encrypted content and import QR codes to decrypt data securely.

### Troubleshooting

- **Missing Dependencies**: Ensure the virtual environment is activated before installing dependencies.
- **Port in Use**: If the default port is busy, use `flask run --port=5051` to start the app on a different port.
- **Python Version Compatibility**: Ensure you're using Python 3.10 or above.

### Security Note

Keep your encryption keys secure and never share them. This application does not log or store any keys or data; always back up your keys and encrypted data safely.

### Contribution and Support

Feel free to contribute by submitting issues or pull requests on GitHub. For any questions, contact us at [hello@0xeop.xyz](mailto:hello@0xeop.xyz).
