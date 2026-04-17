# VPN Kontrol 🔒

A secure VPN monitoring and auto-reconnect application with **enterprise-grade credential protection**.

## ✨ Features

### Core Features
- 🔄 Automatic VPN connection monitoring
- 🔐 Secure credential storage (DPAPI + AES-GCM)
- 📱 TOTP token auto-entry
- 📊 Connection statistics and history
- 🌐 Web-based dashboard
- ⚙️ Auto-reconnect on disconnect
- 📸 QR code TOTP setup

### Security Features (NEW!)
- 🔒 **Windows DPAPI** with entropy
- 🔑 **Master key pattern** (DPAPI + AES-GCM)
- 🛡️ **File ACLs** (user-only access)
- 🧹 **Secure memory handling** (clear after use)
- 📝 **Sanitized logging** (no secret exposure)
- 💼 **Windows Credential Manager** integration
- ✅ **Authenticated encryption** (AES-GCM)
- 🔄 **Automatic migration** from old format

## 🚀 Quick Start

### Installation

1. **Clone or download this repository**
   ```bash
   git clone https://github.com/ofyayla/vpn_kontrol.git
   cd vpn_kontrol
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation (recommended)**
   ```bash
   python check_dependencies.py
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Open web interface**
   - Navigate to: http://127.0.0.1:5000
   - Configure your VPN settings
   - Enter credentials (will be encrypted automatically)

### First-Time Setup

1. **Configure VPN Settings:**
   - VPN URL: Your Pulse Secure URL
   - Username: Your VPN username
   - Password: Your VPN password (encrypted with DPAPI + AES-GCM)
   - TOTP Secret: Your TOTP secret key (or scan QR code)

2. **Enable Auto-Connect (Optional):**
   - Toggle "Auto Connect" in settings
   - Application will reconnect automatically if VPN drops

3. **Set Your VPN IP:**
   - Enter the IP address assigned to you by VPN
   - Used for connection monitoring

## 📋 Requirements

### System Requirements
- **OS:** Windows 10/11 (for full security features)
- **Python:** 3.8 or higher
- **VPN Client:** Pulse Secure (Ivanti Secure Access Client)

### Python Dependencies
```
cryptography>=41.0.0       # AES-GCM encryption
pywin32>=306               # Windows security APIs (optional)
Flask>=2.3.0              # Web interface
pandas>=2.0.0             # Statistics
pyotp>=2.9.0              # TOTP generation
pyautogui>=0.9.54         # Token auto-entry
pygetwindow>=0.0.9        # Window management
opencv-python>=4.8.0      # QR code scanning
```

Install all:
```bash
pip install -r requirements.txt
```

## 🔐 Security Architecture

### How Your Credentials Are Protected

```
┌──────────────────────────────────────────────┐
│  Your Password / TOTP Secret                  │
└──────────────┬───────────────────────────────┘
               │
               ▼
     ┌─────────────────────┐
     │  SecureString        │  ← Cleared from memory after use
     │  (Memory Safety)     │
     └──────────┬───────────┘
                │
                ▼
     ┌─────────────────────┐
     │  AES-GCM Encryption  │  ← Authenticated encryption
     │  (Confidentiality    │     with 256-bit key
     │   + Integrity)       │
     └──────────┬───────────┘
                │
                ▼
     ┌─────────────────────────────┐
     │  Master Key (256-bit)        │
     │  Protected by DPAPI          │  ← Windows user-specific
     │  with Entropy                │
     └──────────┬───────────────────┘
                │
                ▼
     ┌─────────────────────────────┐
     │  File: secrets.dat           │
     │  ACLs: User + SYSTEM only    │  ← Restricted access
     │  Location: %LOCALAPPDATA%    │
     └──────────────────────────────┘
```

**Result:** Your secrets are protected by:
1. Windows DPAPI (per-user encryption)
2. Additional entropy (extra protection layer)
3. AES-GCM (authenticated encryption)
4. File ACLs (access control)
5. Memory clearing (no leftover secrets)

### What This Protects Against
- ✅ Other users on same computer
- ✅ Malicious programs (partial protection)
- ✅ Accidental file exposure
- ✅ Data tampering (integrity checks)
- ✅ Memory dumps (minimized exposure time)
- ✅ Log file leaks (secrets sanitized)

### Limitations
- ⚠️ Cannot protect against malware running as your user while you're logged in
- ⚠️ Cannot protect against admin-level access on your machine
- ⚠️ Cannot protect against keyloggers (use virtual keyboard)

See [SECURITY.md](SECURITY.md) for complete security documentation.

## 📁 File Structure

```
vpn_kontrol/
├── app.py                   # Main application
├── secure_storage.py        # Security module (NEW!)
├── config.json              # Configuration (secrets refs only)
├── vpn_history.json         # Connection history
├── requirements.txt         # Python dependencies
├── SECURITY.md              # Security documentation
├── MIGRATION.md             # Migration guide
├── templates/
│   └── index.html          # Web UI
│
└── %LOCALAPPDATA%\vpn_kontrol\     # Secure storage (NEW!)
    ├── master.key          # DPAPI-protected master key
    ├── entropy.bin         # Random entropy
    └── secrets.dat         # AES-GCM encrypted secrets
```

## 🔄 Migration from Old Version

If you're upgrading from an older version:

**Good news:** Migration is automatic!

1. Update the code
2. Run the application
3. Old secrets are detected and migrated automatically

See [MIGRATION.md](MIGRATION.md) for detailed migration guide.

## ⚙️ Configuration

### Environment Variables

```bash
# Use Windows Credential Manager instead of file storage
$env:VPN_USE_CREDENTIAL_MANAGER = "true"

# Enable debug logging
$env:VPN_KONTROL_DEBUG = "true"

# Bind to specific host (default: 127.0.0.1)
$env:VPN_KONTROL_HOST = "0.0.0.0"

# Custom Fernet key (for non-Windows systems)
$env:VPN_KONTROL_SECRET_KEY = "your-fernet-key-here"
```

### config.json Structure

```json
{
    "vpn_ip": "10.54.2.74",
    "check_interval": 5,
    "vpn_url": "https://vpn.example.com/realm",
    "username": "your.username",
    "password": "secure_storage:password",
    "realm": "YourRealm",
    "totp_secret": "secure_storage:totp_secret",
    "auto_connect": false
}
```

**Note:** `secure_storage:*` are markers. Actual encrypted secrets are in secure storage.

## 🎯 Usage

### Web Interface

Access the dashboard at http://127.0.0.1:5000

**Features:**
- Real-time VPN status
- Connection duration
- Daily statistics (hours/minutes)
- Hourly breakdown chart
- Location toggle (Home/Office)
- Manual connect button
- Settings configuration
- QR code TOTP setup

### API Endpoints

```python
# Get current status
GET /api/status
# Returns: {status, color, duration, stats, ...}

# Save settings
POST /api/save-settings
# Body: {vpn_ip, username, password, totp_secret, ...}

# Connect to VPN
POST /api/connect

# Toggle location
POST /api/toggle-location

# Decode QR code for TOTP
POST /api/decode-qr
# Body: FormData with image file
```

### Programmatic Access

```python
from secure_storage import SecureStorage

# Get secure storage instance
storage = SecureStorage()

# Store a secret
storage.store_secret('my_key', 'my_secret_value')

# Retrieve a secret
value = storage.retrieve_secret('my_key')

# Delete a secret
storage.delete_secret('my_key')

# List stored secrets (keys only)
keys = storage.list_secrets()
```

### Windows Credential Manager

```python
from secure_storage import WindowsCredentialManager

# Check availability
if WindowsCredentialManager.is_available():
    # Store credential
    WindowsCredentialManager.store_credential(
        target='myapp_password',
        username='user@example.com',
        password='secret'
    )
    
    # Retrieve credential
    creds = WindowsCredentialManager.retrieve_credential('myapp_password')
    username, password = creds
```

## 🐛 Troubleshooting

### Common Issues

**Issue:** "TOTP secret dosyaya güvenli olarak yazılamadı" / Secure storage warning
```bash
# This error means the cryptography library is not installed
# Solution:
pip install cryptography

# Or install all dependencies:
pip install -r requirements.txt

# Verify installation:
python check_dependencies.py

# Check if cryptography is installed:
python -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print('✓ cryptography OK')"
```

**Issue:** "Secure storage not initialized"
```bash
# Check LOCALAPPDATA is set
echo $env:LOCALAPPDATA

# Should output: C:\Users\YourName\AppData\Local

# Run dependency check:
python check_dependencies.py
```

**Issue:** "Could not set file ACLs"
```bash
# Install pywin32 for better ACL support
pip install pywin32
```

**Issue:** TOTP token not auto-entering
```bash
# Check TOTP secret is configured correctly
# Ensure base32 format (uppercase letters + numbers 2-7)
# Remove any dashes or spaces

# Test token generation
python -c "import pyotp; print(pyotp.TOTP('YOUR_SECRET').now())"
```

**Issue:** VPN not connecting
```bash
# Check Pulse Secure is installed
Test-Path "C:\Program Files (x86)\Common Files\Pulse Secure\Integration\pulselauncher.exe"

# Check credentials are saved
python -c "from secure_storage import SecureStorage; s = SecureStorage(); print(s.list_secrets())"
```

**Issue:** Migration didn't work
```bash
# Enable debug mode
$env:VPN_KONTROL_DEBUG = "true"
python app.py

# Check for migration messages in console
```

### Debug Mode

```bash
# Enable verbose logging
$env:VPN_KONTROL_DEBUG = "true"
python app.py
```

## 🧪 Testing

### Verify Security Setup

```bash
# Test secure storage
python -c "from secure_storage import SecureStorage; s = SecureStorage(); print('✓ SecureStorage initialized')"

# Test encryption/decryption
python -c "from secure_storage import SecureStorage; s = SecureStorage(); s.store_secret('test', 'value'); assert s.retrieve_secret('test') == 'value'; print('✓ Encryption works')"

# Check file permissions
icacls "$env:LOCALAPPDATA\vpn_kontrol\secrets.dat"

# Should show only your user + SYSTEM
```

### Test TOTP Generation

```python
import pyotp

# Your TOTP secret (base32)
secret = "YOUR_TOTP_SECRET_HERE"

# Generate current token
totp = pyotp.TOTP(secret)
print(f"Current token: {totp.now()}")

# Verify it matches your authenticator app
```

## 📊 Features in Detail

### Auto-Reconnect
- Monitors VPN connection every N seconds
- Automatically launches Pulse Secure if disconnected
- Cooldown period prevents rapid reconnection attempts
- Auto-enters TOTP token when configured

### Statistics Tracking
- **Total Connected Time:** Hours and minutes per day
- **Hourly Breakdown:** Chart showing connection by hour
- **Location Toggle:** Switch between Home/Office modes
- **Persistent History:** Saved across application restarts

### TOTP Integration
- **Manual Entry:** Enter TOTP secret as base32 string
- **QR Code Scan:** Upload QR code image to extract secret
- **Auto-Entry:** Automatically enters token in Pulse dialog
- **Secure Storage:** TOTP secret encrypted with AES-GCM

## 🔧 Advanced Configuration

### Running as Background Service

**Option 1: Use arkaplanda_baslat.vbs**
```bash
# Double-click arkaplanda_baslat.vbs
# Runs silently in background
```

**Option 2: Windows Task Scheduler**
```powershell
# Create scheduled task
$action = New-ScheduledTaskAction -Execute "python.exe" -Argument "$PWD\app.py"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "VPN Kontrol" -Description "VPN monitoring and auto-reconnect"
```

### Custom Storage Location

```python
from secure_storage import SecureStorage

# Use custom directory
storage = SecureStorage(storage_dir="C:\\MySecureFolder")
```

### Custom Entropy

```python
from secure_storage import SecureStorage

# Use custom entropy (32 bytes)
custom_entropy = b"your-32-byte-entropy-value-here!!"
storage = SecureStorage(entropy=custom_entropy)
```

## 📚 Documentation

- **[SECURITY.md](SECURITY.md)** - Complete security documentation
- **[MIGRATION.md](MIGRATION.md)** - Migration guide from old version
- **[requirements.txt](requirements.txt)** - Python dependencies

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📜 License

[Add your license here]

## ⚠️ Disclaimer

This software is provided as-is. While we've implemented multiple security layers, no system is 100% secure. Use at your own risk. Always follow your organization's security policies.

## 🙏 Acknowledgments

Security implementation based on:
- Microsoft DPAPI documentation
- NIST AES-GCM guidelines
- OWASP cryptographic storage best practices
- CWE-256 prevention (plaintext password storage)

## 📞 Support

For issues, questions, or suggestions:
1. Check [SECURITY.md](SECURITY.md) and [MIGRATION.md](MIGRATION.md)
2. Review troubleshooting section above
3. Enable debug mode for more information
4. Open an issue with logs (sanitize secrets first!)

---

**Made with 🔒 by implementing Windows security best practices**
