# Password Manager

A **Password Manager** built in Python for securely storing and managing your credentials. This tool uses encryption to keep your data safe and allows you to manage multiple accounts efficiently.

---

## Features
- **Secure Storage**: Encrypts all data using the **Fernet symmetric encryption** from the `cryptography` library.
- **Master Password**: Protects access to your credentials with a hashed master password.
- **Generate Strong Passwords**: Option to generate random, secure passwords.
- **CRUD Operations**: 
  - Save new credentials.
  - Retrieve stored credentials.
  - Update existing credentials.
  - Delete credentials securely.
- **Clipboard Copy**: Copy username or password to the clipboard securely.
- **Interactive Menu**: Command-line interface with user-friendly prompts.

---

## Setup and Installation
### Prerequisites
- Python 3.7 or above
- Required Libraries: Install using `pip install -r requirements.txt`:
  ```plaintext
  cryptography
  pyperclip
  sqlite3 (builtin)
  ```

### Clone the Repository
```bash
git clone https://github.com/your-username/password-manager.git
cd password-manager
```

### Run the Application
```bash
python password_manager.py
```

---

## Usage
### Initial Setup
1. **Master Password**: On the first run, set a master password to protect your credentials.
2. A new database (`database.db`) will be created in the project directory to store encrypted data.

### Main Menu
1. **Get Credentials**: Retrieve saved credentials by selecting the corresponding service.
2. **Create Credentials**: Add new credentials for an app or service.
3. **Update Credentials**: Update the username or password for an existing account.
4. **Delete Credentials**: Delete saved credentials from the database.
5. **Change Master Password**: Update the master password.
6. **Quit**: Exit the application.

---

## Encryption Details
- **Key Management**: Encryption keys are securely stored in the SQLite database.
- **Encryption Algorithm**: Uses the **Fernet symmetric encryption** scheme for data confidentiality.
- **Master Password Security**: Hashed using `SHA-256` to prevent plaintext storage.

---

## Database Structure
The application uses SQLite for local storage.

### Tables
1. **accounts**
   - `pwId` (INTEGER): Primary key
   - `app` (TEXT): Encrypted app/service name
   - `username` (TEXT): Encrypted username
   - `password` (TEXT): Encrypted password
   - `createdDate` (TEXT): Timestamp for record creation
2. **key**
   - `key` (TEXT): Stores the encryption key
3. **masterPasswordTable**
   - `masterPassword` (TEXT): Stores the hashed master password

---

## Password Generation
Passwords are generated using:
- **Lowercase Letters**: `a-z`
- **Uppercase Letters**: `A-Z`
- **Digits**: `0-9`
- **Symbols**: `!@#$%^&*()...`

You can specify the length of the password.

---

## Dependencies
- **`cryptography`**: For encryption and decryption.
- **`pyperclip`**: To copy data to the clipboard.
- **`sqlite3`**: Built-in SQLite database for local storage.

Install the required packages:
```bash
pip install cryptography pyperclip
```

---

## License
This project is licensed under the [MIT License](LICENSE).

---

## Contributing
Feel free to fork this repository and submit pull requests for improvements or bug fixes.

---

## Author
Developed by **[Shudarsan Regmi](https://github.com/ShudarsanRegmi)**.

--- 
