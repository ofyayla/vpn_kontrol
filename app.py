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

app = Flask(__name__)

# Settings
CONFIG_FILE = "config.json"
DEFAULT_VPN_ASSIGNED_IP = "10.54.2.182"
DEFAULT_KONTROL_SURESI = 10
DATA_FILE = "vpn_history.json"
SENSITIVE_FIELDS = ("password", "totp_secret")
DPAPI_PREFIX = "dpapi:"
FERNET_PREFIX = "fernet:"
CRYPTPROTECT_UI_FORBIDDEN = 0x01
DEBUG_ENABLED = os.environ.get("VPN_KONTROL_DEBUG", "false").lower() == "true"
BIND_HOST = os.environ.get("VPN_KONTROL_HOST", "127.0.0.1")

# Pulse Secure Path
PULSE_LAUNCHER_PATH = r"C:\Program Files (x86)\Common Files\Pulse Secure\Integration\pulselauncher.exe"

_fernet_cipher = None
_fernet_checked = False

def secure_file_permissions(path):
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass

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

def dpapi_encrypt(plain_text):
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.c_ulong),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]

    raw_data = plain_text.encode("utf-8")
    in_buffer = ctypes.create_string_buffer(raw_data, len(raw_data))
    in_blob = DATA_BLOB(len(raw_data), ctypes.cast(in_buffer, ctypes.POINTER(ctypes.c_ubyte)))
    out_blob = DATA_BLOB()

    crypt_protect_data = ctypes.windll.crypt32.CryptProtectData
    crypt_protect_data.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(DATA_BLOB),
    ]
    crypt_protect_data.restype = ctypes.c_bool

    if not crypt_protect_data(
        ctypes.byref(in_blob),
        "vpn_kontrol_secret",
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    ):
        raise ctypes.WinError()

    try:
        encrypted_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return base64.b64encode(encrypted_bytes).decode("ascii")
    finally:
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)

def dpapi_decrypt(cipher_text):
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

def encrypt_sensitive_value(value):
    if not value:
        return ""

    if sys.platform == "win32":
        return f"{DPAPI_PREFIX}{dpapi_encrypt(value)}"

    fernet_cipher = get_fernet_cipher()
    if fernet_cipher:
        encrypted = fernet_cipher.encrypt(value.encode("utf-8")).decode("utf-8")
        return f"{FERNET_PREFIX}{encrypted}"

    raise RuntimeError(
        "Secure secret storage unavailable. On non-Windows systems set VPN_KONTROL_SECRET_KEY (Fernet key)."
    )

def decrypt_sensitive_value(value):
    if not value:
        return ""

    if value.startswith(DPAPI_PREFIX):
        if sys.platform != "win32":
            raise RuntimeError("DPAPI encrypted config can only be decrypted on Windows.")
        return dpapi_decrypt(value[len(DPAPI_PREFIX):])

    if value.startswith(FERNET_PREFIX):
        fernet_cipher = get_fernet_cipher()
        if not fernet_cipher:
            raise RuntimeError("Missing VPN_KONTROL_SECRET_KEY for encrypted config.")
        return fernet_cipher.decrypt(value[len(FERNET_PREFIX):].encode("utf-8")).decode("utf-8")

    # Legacy plaintext value
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
        "auto_connect": False
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
                            config[field] = decrypt_sensitive_value(stored_value)
                            if not (stored_value.startswith(DPAPI_PREFIX) or stored_value.startswith(FERNET_PREFIX)):
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
            continue
        try:
            config_to_save[field] = encrypt_sensitive_value(plain_value)
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
    log_file = "vpn_kontrol_log.txt"
    with open(log_file, "a", encoding="utf-8") as dosya:
        entry = f"{datetime.now()} - {mesaj}"
        try:
            dosya.write(f"{entry}\n")
        except:
             pass 
    secure_file_permissions(log_file)
    
    # Keep last 50 logs in memory for UI
    monitor_state["logs"].append(entry)
    if len(monitor_state["logs"]) > 50:
        monitor_state["logs"].pop(0)

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
        # Clean the secret (remove dashes, spaces, make uppercase)
        clean_secret = secret.replace("-", "").replace(" ", "").upper()
        totp = pyotp.TOTP(clean_secret)
        return totp.now()
    except Exception as e:
        log_yaz(f"TOTP oluşturma hatası: {e}")
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
        
        # Bring window to foreground using SetForegroundWindow
        ctypes.windll.user32.SetForegroundWindow(hwnd)
        t.sleep(0.5)
        
        # Type the token
        pyautogui.typewrite(token, interval=0.05)
        t.sleep(0.3)
        
        # Press Enter to submit
        pyautogui.press('enter')
        
        log_yaz("Token girildi ve gönderildi!")
        return True
    except Exception as e:
        log_yaz(f"Token girme hatası: {e}")
        return False

def vpn_baglan():
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
        args = [
            PULSE_LAUNCHER_PATH,
            "-u", user,
            "-p", pwd,
            "-url", url,
            "-r", realm
        ]
        
        subprocess.Popen(args)
        
        # If TOTP secret is configured, try to auto-enter token
        if monitor_state.get("totp_secret"):
            # Run token entry in a separate thread to not block
            import threading
            token_thread = threading.Thread(target=enter_token_in_pulse_window)
            token_thread.daemon = True
            token_thread.start()
        
        return True
    except Exception as e:
        log_yaz(f"Bağlantı komutu hatası: {e}")
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
    
    # Track current day to detect date changes
    current_day_str = datetime.now().strftime("%Y-%m-%d")
    
    while True:
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
        
        if not is_connected:
            monitor_state["status"] = "VPN Bağlantısı Koptu!"
            monitor_state["status_color"] = "red"
            
            # Log only if status changed or periodically? 
            # To avoid spam, we log only if previous state was different is better but keeping simple for now.
            # Actually, let's just log every disconnect if we are in 'red' state for long time?
            # Existing logic was simple loop.
            
            # Check for Auto Connect
            if monitor_state["auto_connect"]:
                now = time.time()
                if now - last_connection_attempt > COOLDOWN_SECONDS:
                    log_yaz("VPN Koptu. Otomatik bağlanılıyor...")
                    if vpn_baglan():
                         last_connection_attempt = now
                    else:
                         last_connection_attempt = now + 60 # Retry sooner if launch failed
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

        time.sleep(monitor_state["check_interval"])

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
        success = vpn_baglan()
        if success:
            return jsonify({"status": "success", "message": "Bağlantı başlatıldı"})
        else:
            return jsonify({"status": "error", "message": "Bağlantı başlatılamadı"}), 500
    except Exception as e:
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
            "auto_connect": monitor_state["auto_connect"]
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
                "auto_connect": monitor_state["auto_connect"]
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
                "auto_connect": monitor_state["auto_connect"]
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
                "auto_connect": monitor_state["auto_connect"]
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

if __name__ == '__main__':
    app.run(host=BIND_HOST, port=5000, debug=DEBUG_ENABLED)
