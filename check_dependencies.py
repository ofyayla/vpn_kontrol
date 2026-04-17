"""
VPN Kontrol - Dependency Check Script

Run this script to check if all required dependencies are installed correctly.
Usage: python check_dependencies.py
"""

import sys
import os

def check_dependency(module_name, import_statement=None, package_name=None):
    """Check if a dependency is installed"""
    if import_statement is None:
        import_statement = module_name
    if package_name is None:
        package_name = module_name
    
    try:
        __import__(import_statement)
        print(f"✅ {module_name}: Installed")
        return True
    except ImportError as e:
        print(f"❌ {module_name}: NOT installed")
        print(f"   Install with: pip install {package_name}")
        print(f"   Error: {e}")
        return False

def check_windows_features():
    """Check Windows-specific features"""
    if sys.platform != "win32":
        print("⚠️  Not running on Windows. Some features may not work.")
        return False
    
    print("✅ Running on Windows")
    
    # Check LOCALAPPDATA
    localappdata = os.environ.get('LOCALAPPDATA', '')
    if localappdata:
        print(f"✅ LOCALAPPDATA: {localappdata}")
    else:
        print("❌ LOCALAPPDATA environment variable not set")
        return False
    
    # Check if we can access secure storage location
    storage_path = os.path.join(localappdata, 'vpn_kontrol')
    try:
        os.makedirs(storage_path, exist_ok=True)
        test_file = os.path.join(storage_path, 'test.tmp')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        print(f"✅ Secure storage location accessible: {storage_path}")
    except Exception as e:
        print(f"❌ Cannot access secure storage location: {e}")
        return False
    
    return True

def main():
    print("=" * 60)
    print("VPN Kontrol - Dependency Check")
    print("=" * 60)
    print()
    
    all_ok = True
    
    # Check Python version
    print(f"Python Version: {sys.version}")
    if sys.version_info < (3, 8):
        print("⚠️  Python 3.8 or higher is recommended")
    print()
    
    # Check Windows features
    print("Checking Windows Features:")
    print("-" * 60)
    if not check_windows_features():
        all_ok = False
    print()
    
    # Check core dependencies
    print("Checking Core Dependencies:")
    print("-" * 60)
    
    # Critical for secure storage
    if not check_dependency("cryptography", "cryptography", "cryptography>=41.0.0"):
        print("   ⚠️  CRITICAL: Secure storage will NOT work without this!")
        all_ok = False
    
    if sys.platform == "win32":
        if not check_dependency("pywin32", "win32security", "pywin32>=306"):
            print("   ⚠️  RECOMMENDED: Windows ACLs will be limited without this")
    
    # Check web framework
    check_dependency("Flask", "flask", "Flask>=2.3.0")
    
    # Check data processing
    check_dependency("pandas", "pandas", "pandas>=2.0.0")
    
    # Check TOTP
    if not check_dependency("pyotp", "pyotp", "pyotp>=2.9.0"):
        print("   ⚠️  TOTP token generation will not work without this!")
        all_ok = False
    
    # Check GUI automation
    check_dependency("pyautogui", "pyautogui", "pyautogui>=0.9.54")
    check_dependency("pygetwindow", "pygetwindow", "pygetwindow>=0.0.9")
    
    # Check QR code scanning
    check_dependency("opencv", "cv2", "opencv-python>=4.8.0")
    check_dependency("numpy", "numpy", "numpy>=1.24.0")
    
    print()
    print("=" * 60)
    
    if all_ok:
        print("✅ All dependencies are installed correctly!")
        print()
        print("You can now run the application with:")
        print("  python app.py")
        print("  or double-click: baslat.bat")
    else:
        print("⚠️  Some dependencies are missing or issues were found.")
        print()
        print("To install all dependencies at once, run:")
        print("  pip install -r requirements.txt")
        print()
        print("Or install missing packages individually as shown above.")
    
    print("=" * 60)
    
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
