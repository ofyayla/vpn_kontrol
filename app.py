import subprocess
import time
import threading
from datetime import datetime
import json
import os
import sys
import base64
import ctypes
import pandas as pd
from flask import Flask, render_template, jsonify, send_file, request
import io
import signal
import atexit

# Import new secure storage module
from secure_storage import (
    SecureStorage, 
    WindowsACLManager, 
    WindowsCredentialManager,
    SecureString,
    WindowsSecurityError
) 

app = Flask(__name__)

# Settings
CONFIG_FILE = "config.json"
DEFAULT_VPN_ASSIGNED_IP = "10.54.2.182"
DEFAULT_KONTROL_SURESI = 10
DATA_FILE = "vpn_history.json"
SENSITIVE_FIELDS = ("password", "totp_secret")
# Legacy prefixes for migration
DPAPI_PREFIX = "dpapi:"
FERNET_PREFIX = "fernet:"
CRYPTPROTECT_UI_FORBIDDEN = 0x01
DEBUG_ENABLED = os.environ.get("VPN_KONTROL_DEBUG", "false").lower() == "true"
BIND_HOST = os.environ.get("VPN_KONTROL_HOST", "127.0.0.1")
# Use Windows Credential Manager as fallback/alternative
USE_CREDENTIAL_MANAGER = os.environ.get("VPN_USE_CREDENTIAL_MANAGER", "false").lower() == "true"

# Pulse Secure Path
PULSE_LAUNCHER_PATH = r"C:\Program Files (x86)\Common Files\Pulse Secure\Integration\pulselauncher.exe"

# Initialize secure storage (master key pattern with DPAPI + AES-GCM)
try:
    _secure_storage = SecureStorage()
    print("Secure storage initialized with DPAPI + AES-GCM master key pattern")
except Exception as e:
    print(f"Warning: Could not initialize secure storage: {e}")
    _secure_storage = None

_fernet_cipher = None
_fernet_checked = False

# Shutdown flag for graceful termination
_shutdown_flag = threading.Event()

def secure_file_permissions(path):
    """Set secure file permissions using Windows ACLs or Unix permissions"""
    WindowsACLManager.set_user_only_permissions(path)

def get_fernet_cipher():
    global _fernet_cipher, _fernet_checked
    if _fernet_checked:
        return _fernet_cipher
    _fernet_checked = True

    key = os.environ.get("VPN_KONTROL_SECRET_KEY", "").strip()
    if not key:
        return None

    try:
        from cryptography.fernet import Fernet
        _fernet_cipher = Fernet(key.encode("utf-8"))
    except Exception as e:
        print(f"Fernet init error: {e}")
        _fernet_cipher = None
    return _fernet_cipher

# Legacy DPAPI functions kept for migration purposes only
def dpapi_decrypt_legacy(cipher_text):
    """Legacy DPAPI decrypt for migrating old secrets"""
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.c_ulong),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]

    encrypted_bytes = base64.b64decode(cipher_text.encode("ascii"))
    in_buffer = ctypes.create_string_buffer(encrypted_bytes, len(encrypted_bytes))
    in_blob = DATA_BLOB(len(encrypted_bytes), ctypes.cast(in_buffer, ctypes.POINTER(ctypes.c_ubyte)))
    out_blob = DATA_BLOB()

    crypt_unprotect_data = ctypes.windll.crypt32.CryptUnprotectData
    crypt_unprotect_data.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(DATA_BLOB),
    ]
    crypt_unprotect_data.restype = ctypes.c_bool

    if not crypt_unprotect_data(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    ):
        raise ctypes.WinError()

    try:
        decrypted_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return decrypted_bytes.decode("utf-8")
    finally:
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)

def encrypt_sensitive_value(field_name, value):
    """Encrypt and store sensitive value using new secure storage"""
    if not value:
        return ""
    
    if not _secure_storage:
        raise RuntimeError("Secure storage not initialized")
    
    try:
        # Store in secure storage (DPAPI + AES-GCM master key pattern)
        _secure_storage.store_secret(field_name, value)
        
        # Return marker indicating it's stored in secure storage
        return f"secure_storage:{field_name}"
    except Exception as e:
        print(f"Error storing secret '{field_name}': {e}")
        raise RuntimeError(f"Failed to encrypt {field_name}")

def decrypt_sensitive_value(field_name, value):
    """Decrypt sensitive value, handling both legacy and new formats"""
    if not value:
        return ""
    
    # New secure storage format
    if value.startswith("secure_storage:"):
        if not _secure_storage:
            raise RuntimeError("Secure storage not initialized")
        
        stored_key = value.split(":", 1)[1]
        try:
            return _secure_storage.retrieve_secret(stored_key) or ""
        except Exception as e:
            print(f"Error retrieving secret '{stored_key}': {e}")
            return ""
    
    # Legacy DPAPI format - migrate it
    if value.startswith(DPAPI_PREFIX):
        if sys.platform != "win32":
            raise RuntimeError("DPAPI encrypted config can only be decrypted on Windows.")
        try:
            decrypted = dpapi_decrypt_legacy(value[len(DPAPI_PREFIX):])
            # Auto-migrate to new secure storage
            if _secure_storage and decrypted:
                print(f"Migrating legacy DPAPI secret '{field_name}' to new secure storage...")
                _secure_storage.store_secret(field_name, decrypted)
            return decrypted
        except Exception as e:
            print(f"Error decrypting legacy secret '{field_name}': {e}")
            return ""
    
    # Legacy Fernet format
    if value.startswith(FERNET_PREFIX):
        fernet_cipher = get_fernet_cipher()
        if not fernet_cipher:
            raise RuntimeError("Missing VPN_KONTROL_SECRET_KEY for encrypted config.")
        try:
            decrypted = fernet_cipher.decrypt(value[len(FERNET_PREFIX):].encode("utf-8")).decode("utf-8")
            # Auto-migrate to new secure storage
            if _secure_storage and decrypted:
                print(f"Migrating legacy Fernet secret '{field_name}' to new secure storage...")
                _secure_storage.store_secret(field_name, decrypted)
            return decrypted
        except Exception as e:
            print(f"Error decrypting legacy secret '{field_name}': {e}")
            return ""
    
    # Legacy plaintext value - migrate it
    if value and _secure_storage:
        print(f"Migrating plaintext secret '{field_name}' to new secure storage...")
        try:
            _secure_storage.store_secret(field_name, value)
        except Exception as e:
            print(f"Error migrating plaintext secret '{field_name}': {e}")
    
    return value

def persist_config(config_data):
    temp_file = f"{CONFIG_FILE}.tmp"
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=4)
    secure_file_permissions(temp_file)
    os.replace(temp_file, CONFIG_FILE)
    secure_file_permissions(CONFIG_FILE)

def load_config():
    config = {
        "vpn_ip": DEFAULT_VPN_ASSIGNED_IP,
        "check_interval": DEFAULT_KONTROL_SURESI,
        "vpn_url": "",
        "username": "",
        "password": "",
        "realm": "",
        "totp_secret": "",
        "auto_connect": False,
        "max_auto_retry": 3
    }
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                saved_config = json.load(f)
                for key, value in saved_config.items():
                    if key not in SENSITIVE_FIELDS:
                        config[key] = value

                migration_needed = False
                for field in SENSITIVE_FIELDS:
                    stored_value = saved_config.get(field, "")
                    if stored_value:
                        try:
                            config[field] = decrypt_sensitive_value(field, stored_value)
                            # Check if migration is needed
                            if not stored_value.startswith("secure_storage:"):
                                migration_needed = True
                        except Exception as e:
                            print(f"Config decrypt error ({field}): {e}")
                            config[field] = ""
                    else:
                        config[field] = ""

                if migration_needed:
                    save_result = save_config(config)
                    if not save_result["success"] or save_result["warnings"]:
                        print("Warning: Legacy plaintext secrets could not be migrated to encrypted storage.")
        except Exception as e:
            print(f"Config load error: {e}")
    return config

def save_config(new_config):
    warnings = []
    config_to_save = {}
    for key, value in new_config.items():
        if key not in SENSITIVE_FIELDS:
            config_to_save[key] = value

    for field in SENSITIVE_FIELDS:
        plain_value = new_config.get(field, "")
        if not plain_value:
            config_to_save[field] = ""
            # Also clear from secure storage
            if _secure_storage:
                try:
                    _secure_storage.delete_secret(field)
                except Exception:
                    pass
            continue
        try:
            config_to_save[field] = encrypt_sensitive_value(field, plain_value)
        except Exception as e:
            config_to_save[field] = ""
            warnings.append(f"{field} not persisted securely: {e}")

    try:
        persist_config(config_to_save)
        return {"success": True, "warnings": warnings}
    except Exception as e:
        print(f"Config save error: {e}")
        return {"success": False, "warnings": warnings}

# Global State
current_config = load_config()
monitor_state = {
    "vpn_ip": current_config["vpn_ip"],
    "check_interval": int(current_config["check_interval"]),
    "vpn_url": current_config.get("vpn_url", ""),
    "username": current_config.get("username", ""),
    "password": current_config.get("password", ""),
    "realm": current_config.get("realm", ""),
    "totp_secret": current_config.get("totp_secret", ""),
    "auto_connect": current_config.get("auto_connect", False),
    "max_auto_retry": int(current_config.get("max_auto_retry", 3)),
    "auto_retry_count": 0,
    "status": "Unknown",
    "status_color": "gray",
    "total_connected_seconds": 0,
    "hourly_stats": {i: 0 for i in range(24)},
    "last_log_time": time.time(),
    "logs": [],
    "location": "home",  # 'home' or 'office'
    "real_vpn_seconds": 0  # To track actual VPN usage distinct from 'office' 8 hours
}

def log_yaz(mesaj):
    """Write log entry, ensuring no secrets are accidentally logged"""
    log_file = "vpn_kontrol_log.txt"
    
    # Sanitize message to prevent accidental secret logging
    sanitized = mesaj
    for field in SENSITIVE_FIELDS:
        # Replace any potential secrets that might have leaked into logs
        secret_value = monitor_state.get(field, "")
        if secret_value and len(secret_value) > 4:
            # Replace with masked version
            sanitized = sanitized.replace(secret_value, "***REDACTED***")
    
    with open(log_file, "a", encoding="utf-8") as dosya:
        entry = f"{datetime.now()} - {sanitized}"
        try:
            dosya.write(f"{entry}\n")
        except:
             pass 
    secure_file_permissions(log_file)
    
    # Keep last 50 logs in memory for UI
    monitor_state["logs"].append(entry)
    if len(monitor_state["logs"]) > 50:
        monitor_state["logs"].pop(0)

def detect_vpn_ip():
    """Detect the actual VPN IP address from network interfaces"""
    try:
        if sys.platform != "win32":
            return None
        
        # Use PowerShell to get network adapter information
        # Look for adapters with Pulse, Ivanti, Juniper, or VPN-related names
        ps_cmd = '''
        Get-NetAdapter | Where-Object {
            $_.Status -eq 'Up' -and (
                $_.InterfaceDescription -like '*Pulse*' -or
                $_.InterfaceDescription -like '*Ivanti*' -or
                $_.InterfaceDescription -like '*Juniper*' -or
                $_.Name -like '*VPN*' -or
                $_.Name -like '*Pulse*'
            )
        } | ForEach-Object {
            $adapter = $_
            Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
            Select-Object -ExpandProperty IPAddress
        }
        '''
        
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=5
        )
        
        if result.returncode == 0 and result.stdout:
            ip_addresses = result.stdout.decode('utf-8').strip().split('\n')
            # Return the first valid IP found
            for ip in ip_addresses:
                ip = ip.strip()
                if ip and not ip.startswith('169.254'):  # Ignore APIPA addresses
                    return ip
        
        return None
    except Exception as e:
        if DEBUG_ENABLED:
            print(f"VPN IP Detection Error: {e}")
        return None

def vpn_baglanti_kontrol_et(ip):
    try:
        if sys.platform == "win32":
            args = ["ping", "-n", "1", ip]
            creationflags = subprocess.CREATE_NO_WINDOW
        else:
            args = ["ping", "-c", "1", ip]
            creationflags = 0

        result = subprocess.run(
            args,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=creationflags
        )
        return result.returncode == 0
    except Exception as e:
        print(f"Ping Error: {e}")
        return False

import pyotp
import pyautogui
import pygetwindow as gw

def get_totp_token():
    """Generate current TOTP token from secret"""
    secret = monitor_state.get("totp_secret", "")
    if not secret:
        return None
    try:
        # Use SecureString for better memory handling
        with SecureString(secret) as secure_secret:
            # Clean the secret (remove dashes, spaces, make uppercase)
            clean_secret = secure_secret.get().replace("-", "").replace(" ", "").upper()
            
            with SecureString(clean_secret) as secure_clean:
                totp = pyotp.TOTP(secure_clean.get())
                token = totp.now()
                return token
    except Exception as e:
        # Don't log the actual secret in error messages
        log_yaz(f"TOTP oluşturma hatası: {type(e).__name__}")
        return None

def enter_token_in_pulse_window():
    """Find Pulse Secure token window and enter TOTP"""
    import time as t
    
    token = get_totp_token()
    if not token:
        log_yaz("HATA: TOTP token oluşturulamadı. Secret key kontrol edin.")
        return False
    
    log_yaz("TOTP token üretildi.")
    
    # Wait for the Pulse window to appear
    max_wait = 30  # seconds
    pulse_window = None
    
    for i in range(max_wait):
        t.sleep(1)
        if i % 5 == 0:
            log_yaz(f"Token penceresi araniyor... ({i}/{max_wait}s)")
        # Look for Pulse Secure windows
        windows = gw.getWindowsWithTitle("Ivanti Secure Access Client")
        if not windows:
            windows = gw.getWindowsWithTitle("Pulse Secure")
        if not windows:
            windows = gw.getWindowsWithTitle("Connect to:")
        if not windows:
            windows = gw.getWindowsWithTitle("Secondary")
        
        if windows:
            pulse_window = windows[0]
            break
    
    if not pulse_window:
        log_yaz("HATA: Pulse Secure token penceresi bulunamadı.")
        return False
    
    log_yaz("Token penceresi bulundu. Token giriliyor...")
    
    try:
        # Use win32gui for more reliable window activation
        import ctypes
        
        # Get window handle
        hwnd = pulse_window._hWnd
        
        # Try multiple times to bring window to foreground
        for attempt in range(3):
            # Restore if minimized
            if pulse_window.isMinimized:
                pulse_window.restore()
                t.sleep(0.3)
            
            # Bring window to foreground using SetForegroundWindow
            ctypes.windll.user32.SetForegroundWindow(hwnd)
            t.sleep(0.5)
            
            # Verify window is actually in focus
            active_hwnd = ctypes.windll.user32.GetForegroundWindow()
            if active_hwnd == hwnd:
                log_yaz(f"Pencere aktif hale getirildi (deneme {attempt + 1})")
                break
            else:
                log_yaz(f"Pencere aktif edilemedi, tekrar deneniyor... ({attempt + 1}/3)")
                t.sleep(0.5)
        else:
            log_yaz("UYARI: Pencere tam olarak aktif edilemedi, yine de devam ediliyor...")
        
        # Additional wait to ensure window is ready
        t.sleep(0.5)
        
        # Click in the center of the window to ensure focus on the input field
        # This helps ensure the token field is selected
        try:
            center_x = pulse_window.left + pulse_window.width // 2
            center_y = pulse_window.top + pulse_window.height // 2
            pyautogui.click(center_x, center_y)
            t.sleep(0.3)
            log_yaz("Token alanı seçildi")
        except Exception as click_error:
            log_yaz(f"UYARI: Token alanı tıklanamadı: {click_error}")
        
        # Clear any existing content in the field (press Ctrl+A then Delete)
        pyautogui.hotkey('ctrl', 'a')
        t.sleep(0.1)
        pyautogui.press('delete')
        t.sleep(0.2)
        
        # Type the token with a longer interval for reliability
        # Using typewrite with increased interval for more reliable input
        pyautogui.typewrite(token, interval=0.1)
        t.sleep(0.5)
        
        # Press Enter to submit
        pyautogui.press('enter')
        
        log_yaz("Token girildi ve gönderildi!")
        return True
    except Exception as e:
        log_yaz(f"Token girme hatası: {e}")
        return False

def vpn_baglan():
    """Connect to VPN using Pulse Secure launcher"""
    if not os.path.exists(PULSE_LAUNCHER_PATH):
        log_yaz("HATA: pulselauncher.exe bulunamadı.")
        return False
    
    url = monitor_state["vpn_url"]
    user = monitor_state["username"]
    pwd = monitor_state["password"]
    realm = monitor_state["realm"] if monitor_state["realm"] else "Albarakatech_Realm"
    
    if not url or not user or not pwd:
        log_yaz("HATA: Otomatik bağlantı için URL, Kullanıcı Adı ve Şifre gerekli.")
        return False
        
    log_yaz(f"Otomatik bağlantı deneniyor... ({url} / {realm})")
    
    try:
        # Use SecureString to minimize password exposure in memory
        with SecureString(pwd) as secure_pwd:
            args = [
                PULSE_LAUNCHER_PATH,
                "-u", user,
                "-p", secure_pwd.get(),  # Get password only when needed
                "-url", url,
                "-r", realm
            ]
            
            # Start process
            subprocess.Popen(args)
        
        # Password is now cleared from SecureString
        
        # If TOTP secret is configured, try to auto-enter token
        if monitor_state.get("totp_secret"):
            # Run token entry in a separate thread to not block
            import threading
            token_thread = threading.Thread(target=enter_token_in_pulse_window)
            token_thread.daemon = True
            token_thread.start()
        
        return True
    except Exception as e:
        # Don't log the actual password in error messages
        log_yaz(f"Bağlantı komutu hatası: {type(e).__name__}")
        return False

def load_history():
    data = read_json_safe()
    try:
        today_str = datetime.now().strftime("%Y-%m-%d")
        if today_str in data:
            today_data = data[today_str]
            monitor_state["total_connected_seconds"] = today_data.get("total_seconds", 0)
            monitor_state["real_vpn_seconds"] = today_data.get("real_vpn_seconds", today_data.get("total_seconds", 0)) # Fallback
            monitor_state["location"] = today_data.get("location", "home")
            saved_hourly = today_data.get("hourly", {})
            for k, v in saved_hourly.items():
                monitor_state["hourly_stats"][int(k)] = v
    except Exception as e:
        print(f"History load error: {e}")

def save_history():
    try:
        data = read_json_safe()
        
        today_str = datetime.now().strftime("%Y-%m-%d")
        data[today_str] = {
            "total_seconds": monitor_state["total_connected_seconds"],
            "real_vpn_seconds": monitor_state["real_vpn_seconds"],
            "hourly": monitor_state["hourly_stats"],
            "location": monitor_state["location"]
        }
        
        write_json_safe(data)
    except Exception as e:
        print(f"History save error: {e}")

def monitor_loop():
    print("Monitor Thread Started")
    load_history()
    log_yaz("Monitoring Started")
    
    last_connection_attempt = 0
    COOLDOWN_SECONDS = 30 # 30 seconds cooldown between auto-reconnect attempts
    last_ip_check = 0
    IP_CHECK_INTERVAL = 60  # Check for IP changes every 60 seconds
    
    # Track current day to detect date changes
    current_day_str = datetime.now().strftime("%Y-%m-%d")
    
    while not _shutdown_flag.is_set():
        try:
            # Check if day changed
            now_day_str = datetime.now().strftime("%Y-%m-%d")
            if now_day_str != current_day_str:
                log_yaz(f"Yeni güne geçiş tespit edildi: {now_day_str}. Sayaçlar sıfırlanıyor.")
                
                # Reset counters for the new day
                monitor_state["total_connected_seconds"] = 0
                monitor_state["real_vpn_seconds"] = 0
                monitor_state["hourly_stats"] = {i: 0 for i in range(24)}
                monitor_state["location"] = "home" # Reset location to home default
                
                current_day_str = now_day_str
                # Save immediately to initialize the new day in file
                save_history()

            is_connected = vpn_baglanti_kontrol_et(monitor_state["vpn_ip"])
            
            # Periodically check if VPN IP has changed (when connected)
            if is_connected:
                now = time.time()
                if now - last_ip_check > IP_CHECK_INTERVAL:
                    last_ip_check = now
                    detected_ip = detect_vpn_ip()
                    
                    if detected_ip and detected_ip != monitor_state["vpn_ip"]:
                        old_ip = monitor_state["vpn_ip"]
                        monitor_state["vpn_ip"] = detected_ip
                        log_yaz(f"VPN IP değişikliği tespit edildi: {old_ip} -> {detected_ip}")
                        
                        # Update config file
                        try:
                            save_result = save_config({
                                "vpn_ip": detected_ip,
                                "check_interval": monitor_state["check_interval"],
                                "vpn_url": monitor_state["vpn_url"],
                                "username": monitor_state["username"],
                                "password": monitor_state["password"],
                                "realm": monitor_state["realm"],
                                "totp_secret": monitor_state["totp_secret"],
                                "auto_connect": monitor_state["auto_connect"],
                                "max_auto_retry": monitor_state["max_auto_retry"]
                            })
                            if save_result["success"]:
                                log_yaz("VPN IP konfigürasyonda güncellendi")
                            else:
                                log_yaz("UYARI: VPN IP konfigürasyona kaydedilemedi")
                        except Exception as e:
                            log_yaz(f"VPN IP kaydetme hatası: {e}")
            
            if not is_connected:
                monitor_state["status"] = "VPN Bağlantısı Koptu!"
                monitor_state["status_color"] = "red"
                
                # Log only if status changed or periodically? 
                # To avoid spam, we log only if previous state was different is better but keeping simple for now.
                # Actually, let's just log every disconnect if we are in 'red' state for long time?
                # Existing logic was simple loop.
                
                # Check for Auto Connect
                if monitor_state["auto_connect"]:
                    max_retries = monitor_state.get("max_auto_retry", 3)
                    retry_count = monitor_state.get("auto_retry_count", 0)
                    
                    # Check if max retries exceeded
                    if retry_count >= max_retries:
                        if retry_count == max_retries:  # Log only once
                            log_yaz(f"UYARI: Maksimum deneme sayısına ulaşıldı ({max_retries}). Otomatik bağlantı durduruluyor.")
                            log_yaz("Yeniden denemek için manuel bağlantı yapın veya ayarları güncelleyin.")
                            monitor_state["auto_retry_count"] = max_retries + 1  # Prevent repeated logging
                    else:
                        now = time.time()
                        if now - last_connection_attempt > COOLDOWN_SECONDS:
                            log_yaz(f"VPN Koptu. Otomatik bağlanılıyor... (Deneme {retry_count + 1}/{max_retries})")
                            if vpn_baglan():
                                last_connection_attempt = now
                                monitor_state["auto_retry_count"] = retry_count + 1
                            else:
                                last_connection_attempt = now + 60 # Retry sooner if launch failed
                                monitor_state["auto_retry_count"] = retry_count + 1
                        else:
                            # In cooldown - log remaining time
                            remaining = int(COOLDOWN_SECONDS - (now - last_connection_attempt))
                            if remaining % 10 == 0:  # Log every 10 seconds
                                log_yaz(f"Bekleniyor... ({remaining}s)")
                else:
                     log_yaz("Otomatik bağlantı kapalı.")
                     # Just log if not already spamming?
                     # To prevent log spam, we could check if we already logged 'Disconnected' recently 
                     # but original code was simple. Let's keep it simple but maybe log periodically.
                     pass
                     
            else:
                monitor_state["status"] = "VPN Bağlantısı Aktif"
                monitor_state["status_color"] = "green"
                last_connection_attempt = 0 # Reset cooldown on success
                monitor_state["auto_retry_count"] = 0  # Reset retry counter on successful connection
                
                # Stats update
                now = datetime.now()
                # Stats update
                now = datetime.now()
                monitor_state["hourly_stats"][now.hour] = monitor_state["hourly_stats"].get(now.hour, 0) + monitor_state["check_interval"]
                monitor_state["real_vpn_seconds"] += monitor_state["check_interval"]
                
                # Update effective total based on location
                if monitor_state["location"] == "office":
                     monitor_state["total_connected_seconds"] = 28800 # 8 hours
                else:
                     monitor_state["total_connected_seconds"] = monitor_state["real_vpn_seconds"]

                # Periodic logging
                if time.time() - monitor_state["last_log_time"] >= 60:
                    hours = monitor_state["total_connected_seconds"] // 3600
                    minutes = (monitor_state["total_connected_seconds"] % 3600) // 60
                    log_yaz(f"VPN Aktif - Toplam Süre: {int(hours):02d}:{int(minutes):02d}")
                    monitor_state["last_log_time"] = time.time()
                    save_history()

            # Sleep in small intervals to allow quick shutdown
            for _ in range(monitor_state["check_interval"]):
                if _shutdown_flag.is_set():
                    break
                time.sleep(1)
                    
        except Exception as e:
            log_yaz(f"Monitor loop error: {e}")
            if not _shutdown_flag.is_set():
                time.sleep(5)  # Wait a bit before retrying
    
    log_yaz("Monitoring Stopped")
    print("Monitor Thread Stopped")

# File Lock for thread safety
file_lock = threading.Lock()

def read_json_safe():
    with file_lock:
        if not os.path.exists(DATA_FILE):
            return {}
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return {}

def write_json_safe(data):
    with file_lock:
        try:
            # Atomic write pattern
            temp_file = f"{DATA_FILE}.tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            secure_file_permissions(temp_file)
            os.replace(temp_file, DATA_FILE)
            secure_file_permissions(DATA_FILE)
        except Exception as e:
            print(f"Save error: {e}")

def cleanup_on_shutdown():
    """Cleanup function called on program exit"""
    print("Shutting down gracefully...")
    _shutdown_flag.set()
    log_yaz("Application shutting down")
    # Give the monitor thread a moment to finish
    time.sleep(2)
    print("Shutdown complete")

# Register cleanup handlers
atexit.register(cleanup_on_shutdown)

def signal_handler(signum, frame):
    """Handle interrupt signals"""
    print(f"\nReceived signal {signum}, shutting down...")
    cleanup_on_shutdown()
    sys.exit(0)

# Register signal handlers for Windows
if sys.platform == "win32":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGBREAK, signal_handler)
else:
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

# Start background thread once:
# - debug=False: start directly
# - debug=True: start only in reloader child process
if (not DEBUG_ENABLED) or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
    thread = threading.Thread(target=monitor_loop, daemon=True)
    thread.start()

@app.route('/')
def index():
    return render_template('index.html')

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data: blob:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    return response

@app.route('/api/status')
def api_status():
    total_sec = monitor_state["total_connected_seconds"]
    hours = total_sec // 3600
    minutes = (total_sec % 3600) // 60
    
    return jsonify({
        "status": monitor_state["status"],
        "color": monitor_state["status_color"],
        "total_time": f"{int(hours):02d}:{int(minutes):02d}",
        "hourly_stats": monitor_state["hourly_stats"],
        "logs": monitor_state["logs"][-20:], # Return last 20 logs
        "location": monitor_state["location"]
    })

@app.route('/api/reconnect', methods=['POST'])
def api_reconnect():
    """Manually trigger VPN reconnection"""
    try:
        log_yaz("Manuel bağlantı isteği alındı...")
        # Reset retry counter on manual connection
        monitor_state["auto_retry_count"] = 0
        success = vpn_baglan()
        if success:
            return jsonify({"status": "success", "message": "Bağlantı başlatıldı"})
        else:
            return jsonify({"status": "error", "message": "Bağlantı başlatılamadı"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/detect-ip', methods=['POST'])
def api_detect_ip():
    """Manually detect and update VPN IP address"""
    try:
        log_yaz("VPN IP algılama isteği alındı...")
        detected_ip = detect_vpn_ip()
        
        if not detected_ip:
            return jsonify({
                "status": "error", 
                "message": "VPN IP adresi algılanamadı. VPN bağlı olduğundan emin olun."
            }), 404
        
        old_ip = monitor_state["vpn_ip"]
        
        if detected_ip == old_ip:
            return jsonify({
                "status": "success",
                "message": f"VPN IP değişmedi: {detected_ip}",
                "ip": detected_ip,
                "changed": False
            })
        
        # Update monitor state
        monitor_state["vpn_ip"] = detected_ip
        
        # Save to config
        save_result = save_config({
            "vpn_ip": detected_ip,
            "check_interval": monitor_state["check_interval"],
            "vpn_url": monitor_state["vpn_url"],
            "username": monitor_state["username"],
            "password": monitor_state["password"],
            "realm": monitor_state["realm"],
            "totp_secret": monitor_state["totp_secret"],
            "auto_connect": monitor_state["auto_connect"],
            "max_auto_retry": monitor_state["max_auto_retry"]
        })
        
        if save_result["success"]:
            log_yaz(f"VPN IP güncellendi: {old_ip} -> {detected_ip}")
            return jsonify({
                "status": "success",
                "message": f"VPN IP güncellendi: {old_ip} → {detected_ip}",
                "old_ip": old_ip,
                "new_ip": detected_ip,
                "changed": True
            })
        else:
            return jsonify({
                "status": "error",
                "message": "VPN IP algılandı ancak kaydedilemedi"
            }), 500
            
    except Exception as e:
        log_yaz(f"VPN IP algılama hatası: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/history')
def api_history():
    history_data = []
    history_data = []
    try:
        data = read_json_safe()
        # Sort by date
        for date_str in sorted(data.keys(), reverse=True):
            day_data = data[date_str]
            history_data.append({
                "date": date_str,
                "total_seconds": day_data.get("total_seconds", 0),
                "location": day_data.get("location", "home")
            })
    except Exception as e:
        print(f"Error reading history: {e}")
            
    return jsonify(history_data)

@app.route('/api/set_location', methods=['POST'])
def api_set_location():
    try:
        data = request.json
        date_str = data.get('date')
        location = data.get('location')
        
        if not date_str or not location:
            return jsonify({"error": "Missing fields"}), 400
            
        today_str = datetime.now().strftime("%Y-%m-%d")
        
        # If setting for today
        if date_str == today_str:
            monitor_state["location"] = location
            if location == "office":
                monitor_state["total_connected_seconds"] = 28800
                log_yaz("Konum değiştirildi: Ofis (8 saat tanımlandı)")
            else:
                monitor_state["total_connected_seconds"] = monitor_state["real_vpn_seconds"]
                log_yaz("Konum değiştirildi: Ev")
            save_history()
            return jsonify({"status": "success", "message": "Location updated for today"})
        
        # If setting for past date
        else:

            history = read_json_safe()
            if not history:
                 return jsonify({"error": "No history"}), 404
            
            if date_str in history:
                history[date_str]["location"] = location
                
                if location == "office":
                    # Backup real time if not already backed up
                    if "real_vpn_seconds" not in history[date_str]:
                         curr_total = history[date_str].get("total_seconds", 0)
                         # If current total is 0 but we have hourly data, calculate it
                         if curr_total == 0 and "hourly" in history[date_str]:
                             curr_total = sum(history[date_str]["hourly"].values())
                         history[date_str]["real_vpn_seconds"] = curr_total
                         
                    history[date_str]["total_seconds"] = 28800
                else:
                    # Restore from backup
                    restored_val = history[date_str].get("real_vpn_seconds", 0)
                    # Fallback: calculate from hourly if restored value is 0
                    if restored_val == 0 and "hourly" in history[date_str]:
                         restored_val = sum(history[date_str]["hourly"].values())
                    history[date_str]["total_seconds"] = restored_val
                
                write_json_safe(history)
                    
                return jsonify({"status": "success", "message": "Location updated for history"})
            else:
                return jsonify({"error": "Date not found"}), 404
                
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/history/<date_str>')
def api_history_detail(date_str):
    try:
        data = read_json_safe()
        if not data:
             return jsonify({"error": "No data found"}), 404
            
        if date_str in data:
            return jsonify(data[date_str])
        else:
            return jsonify({"hourly": {i: 0 for i in range(24)}, "total_seconds": 0})
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/export')
def api_export():
    try:
        data = read_json_safe()
        if not data:
             return jsonify({"error": "No data found"}), 404
        
        # Prepare data for DataFrame
        rows = []
        for date_str, day_data in data.items():
            total_sec = day_data.get("total_seconds", 0)
            hours = total_sec // 3600
            minutes = (total_sec % 3600) // 60
            
            row = {
                "Tarih": date_str,
                "Toplam Saniye": total_sec,
                "Süre": f"{int(hours):02d}:{int(minutes):02d}",
                "Durum": "Tamamlandı" if total_sec >= (8 * 3600) else "Eksik"
            }
            # Flatten hourly stats if needed, or just summary
            rows.append(row)
            
        df = pd.DataFrame(rows)
        df = df.sort_values(by="Tarih")
        
        # Create Excel file in memory
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='VPN Takip')
            
        output.seek(0)
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='vpn_gecmis.xlsx'
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    if request.method == 'GET':
        return jsonify({
            "vpn_ip": monitor_state["vpn_ip"],
            "check_interval": monitor_state["check_interval"],
            "vpn_url": monitor_state["vpn_url"],
            "username": monitor_state["username"],
            "realm": monitor_state.get("realm", ""),
            "has_password": bool(monitor_state["password"]),
            "has_totp_secret": bool(monitor_state.get("totp_secret", "")),
            "auto_connect": monitor_state["auto_connect"],
            "max_auto_retry": monitor_state.get("max_auto_retry", 3),
            "auto_retry_count": monitor_state.get("auto_retry_count", 0)
        })
    
    elif request.method == 'POST':
        try:
            data = request.json
            monitor_state["vpn_ip"] = data.get('vpn_ip', monitor_state["vpn_ip"])
            monitor_state["check_interval"] = int(data.get('check_interval', monitor_state["check_interval"]))
            monitor_state["vpn_url"] = data.get('vpn_url', "")
            monitor_state["username"] = data.get('username', "")
            monitor_state["realm"] = data.get('realm', "")
            monitor_state["auto_connect"] = data.get('auto_connect', False)
            monitor_state["max_auto_retry"] = int(data.get('max_auto_retry', 3))
            
            # Reset retry counter when settings are updated
            if "max_auto_retry" in data:
                monitor_state["auto_retry_count"] = 0
                log_yaz(f"Maksimum otomatik bağlantı denemesi güncellendi: {monitor_state['max_auto_retry']}")

            if data.get("clear_password"):
                monitor_state["password"] = ""
            elif "password" in data:
                monitor_state["password"] = data.get("password", "")

            if data.get("clear_totp_secret"):
                monitor_state["totp_secret"] = ""
            elif "totp_secret" in data:
                monitor_state["totp_secret"] = data.get("totp_secret", "")
            
            # Save to Config
            save_result = save_config({
                "vpn_ip": monitor_state["vpn_ip"],
                "check_interval": monitor_state["check_interval"],
                "vpn_url": monitor_state["vpn_url"],
                "username": monitor_state["username"],
                "password": monitor_state["password"],
                "realm": monitor_state["realm"],
                "totp_secret": monitor_state["totp_secret"],
                "auto_connect": monitor_state["auto_connect"],
                "max_auto_retry": monitor_state["max_auto_retry"]
            })

            if not save_result["success"]:
                return jsonify({"error": "Ayarlar kaydedilemedi."}), 500
            
            log_yaz(f"Ayarlar güncellendi: IP={monitor_state['vpn_ip']}, OtoConnect={monitor_state['auto_connect']}")
            response_payload = {"status": "success", "message": "Settings saved"}
            if save_result["warnings"]:
                response_payload["warning"] = "Bazı gizli alanlar güvenli biçimde kaydedilemedi."
            return jsonify(response_payload)
            
        except Exception as e:
            return jsonify({"error": str(e)}), 500

@app.route('/api/decode-qr', methods=['POST'])
def decode_qr():
    """Decode QR code image and extract TOTP secret"""
    try:
        import cv2
        import numpy as np
        import base64
        import urllib.parse
        
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        # Read image using opencv
        file_bytes = np.frombuffer(file.read(), np.uint8)
        image = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
        
        if image is None:
            return jsonify({"error": "Resim okunamadı"}), 400
        
        # Decode QR code using OpenCV
        detector = cv2.QRCodeDetector()
        qr_data, bbox, _ = detector.detectAndDecode(image)
        
        if not qr_data:
            return jsonify({"error": "QR kod bulunamadı"}), 400
        
        # Check if it's an otpauth-migration URL
        if qr_data.startswith('otpauth-migration://'):
            # Parse migration URL
            parsed = urllib.parse.urlparse(qr_data)
            params = urllib.parse.parse_qs(parsed.query)
            data_encoded = params.get('data', [''])[0]
            
            # Decode base64 data
            data_bytes = base64.b64decode(data_encoded)
            
            # Extract secret (bytes 4-20 in protobuf structure)
            secret_raw = data_bytes[4:20]
            
            # Convert raw bytes to base32
            totp_secret = base64.b32encode(secret_raw).decode().rstrip('=')
            
            # Auto-save to monitor_state and config
            monitor_state["totp_secret"] = totp_secret
            save_result = save_config({
                "vpn_ip": monitor_state["vpn_ip"],
                "check_interval": monitor_state["check_interval"],
                "vpn_url": monitor_state["vpn_url"],
                "username": monitor_state["username"],
                "password": monitor_state["password"],
                "realm": monitor_state["realm"],
                "totp_secret": totp_secret,
                "auto_connect": monitor_state["auto_connect"],
                "max_auto_retry": monitor_state.get("max_auto_retry", 3)
            })
            if not save_result["success"]:
                return jsonify({"error": "TOTP Secret güvenli olarak kaydedilemedi"}), 500
            
            log_yaz(f"QR'dan TOTP Secret kaydedildi")
            
            response_payload = {
                "status": "success",
                "message": f"TOTP Secret kaydedildi! Artık token otomatik girilecek."
            }
            if save_result["warnings"]:
                response_payload["warning"] = "TOTP secret dosyaya güvenli olarak yazılamadı. Uygulama kapanınca tekrar girmeniz gerekir."
            return jsonify(response_payload)
        
        # Check if it's a standard otpauth URL
        elif qr_data.startswith('otpauth://totp/'):
            parsed = urllib.parse.urlparse(qr_data)
            params = urllib.parse.parse_qs(parsed.query)
            secret = params.get('secret', [''])[0]
            
            # Auto-save to monitor_state and config
            monitor_state["totp_secret"] = secret
            save_result = save_config({
                "vpn_ip": monitor_state["vpn_ip"],
                "check_interval": monitor_state["check_interval"],
                "vpn_url": monitor_state["vpn_url"],
                "username": monitor_state["username"],
                "password": monitor_state["password"],
                "realm": monitor_state["realm"],
                "totp_secret": secret,
                "auto_connect": monitor_state["auto_connect"],
                "max_auto_retry": monitor_state.get("max_auto_retry", 3)
            })
            if not save_result["success"]:
                return jsonify({"error": "TOTP Secret güvenli olarak kaydedilemedi"}), 500
            
            log_yaz(f"QR'dan TOTP Secret kaydedildi")
            
            response_payload = {
                "status": "success",
                "message": "TOTP Secret kaydedildi! Artık token otomatik girilecek."
            }
            if save_result["warnings"]:
                response_payload["warning"] = "TOTP secret dosyaya güvenli olarak yazılamadı. Uygulama kapanınca tekrar girmeniz gerekir."
            return jsonify(response_payload)
        
        else:
            return jsonify({"error": f"Desteklenmeyen QR formatı: {qr_data[:50]}..."}), 400
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/shutdown', methods=['POST'])
def api_shutdown():
    """Gracefully shutdown the application"""
    try:
        log_yaz("Uygulama kapatma isteği alındı")
        
        def shutdown_server():
            time.sleep(1)  # Give time for response to be sent
            cleanup_on_shutdown()
            os._exit(0)
        
        # Run shutdown in a separate thread
        threading.Thread(target=shutdown_server, daemon=True).start()
        
        return jsonify({
            "status": "success",
            "message": "Uygulama kapatılıyor..."
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(host=BIND_HOST, port=5000, debug=DEBUG_ENABLED)
