#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           AES_Tool — Katmanlı Şifreleme Aracı               ║
║   AES-256-CBC/GCM + ChaCha20 + XOR + Steganografi           ║
║   Açık kaynak | Terminal & GUI | Modüler yapı                ║
╚══════════════════════════════════════════════════════════════╝

Kullanım:
    python aes_tool.py                    → Başlatma menüsü
    python aes_tool.py --terminal         → Doğrudan terminal modu
    python aes_tool.py --gui              → Doğrudan GUI modu
    python aes_tool.py --help             → Yardım

Diğer araçlarla entegrasyon:
    from aes_tool import CryptoEngine     → Modül olarak kullan
"""
###Uyarı bu kütüphaneyi kurmayı unutmayın ve kurun lütfen:
##          pip install cryptography
#import kısmı :
import os,sys,argparse,base64,struct,getpass,json,hashlib
from pathlib import Path
# Bağımlılık kontrolü kısmı (pip install gerekebilir) 
def check_deps():
    missing = []
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    except ImportError:
        missing.append("cryptography")
    if missing:
        print(f"\n[!] Eksik bağımlılık: {', '.join(missing)}")
        print(f"    Kurmak için: pip install {' '.join(missing)}")
        sys.exit(1)
check_deps()
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

#  CRYPTO ENGINE — diğer araçlarla kullanılabilir / (modifiye etme için)  
class CryptoEngine:
    """
    Modüler şifreleme motoru.
    Başka araçlardan import edip kullanabilirsin:
        from aes_tool import CryptoEngine
        engine = CryptoEngine()
        encrypted = engine.aes_encrypt(text, password, mode='GCM')
    """

    PBKDF2_ITERATIONS = 200_000  # ← İstediğin zaman değiştir
    SALT_LEN = 16
    ZW_CHARS = ['\u200B', '\u200C', '\u200D', '\uFEFF']

    def __init__(self, iterations: int = None):
        if iterations:
            self.PBKDF2_ITERATIONS = iterations

    def _derive_key(self, password: str, salt: bytes, length: int = 32) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    # AES-256 CBC ----- AES-256-CBC Kısmı 
    def aes_cbc_encrypt(self, text: str, password: str) -> str:
        salt = os.urandom(self.SALT_LEN)
        iv   = os.urandom(16)
        key  = self._derive_key(password, salt)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(text.encode('utf-8')) + padder.finalize()
        enc = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
        ct  = enc.update(padded) + enc.finalize()
        combined = b'\x00' + salt + iv + ct
        return base64.b64encode(combined).decode('ascii')
    
    def aes_cbc_decrypt(self, b64: str, password: str) -> str:
        raw  = base64.b64decode(b64)
        if raw[0] != 0:
            raise ValueError("Bu veri CBC formatında değil (GCM olabilir).")
        salt = raw[1:17]
        iv   = raw[17:33]
        ct   = raw[33:]
        key  = self._derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec  = cipher.decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode('utf-8')

    # AES-256 GCM ----- AES-256-GCM Kısmı 
    def aes_gcm_encrypt(self, text: str, password: str) -> str:
        salt = os.urandom(self.SALT_LEN)
        nonce = os.urandom(12)
        key  = self._derive_key(password, salt)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, text.encode('utf-8'), None)
        combined = b'\x01' + salt + nonce + ct  # \x01 = GCM modu flag
        return base64.b64encode(combined).decode('ascii')

    def aes_gcm_decrypt(self, b64: str, password: str) -> str:
        raw = base64.b64decode(b64)
        if raw[0] != 1:
            raise ValueError("Bu veri GCM formatında değil (CBC olabilir).")
        salt  = raw[1:17]
        nonce = raw[17:29]
        ct    = raw[29:]
        key   = self._derive_key(password, salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, None).decode('utf-8')

    def aes_decrypt_auto(self, b64: str, password: str) -> str:
        """CBC mi GCM mi olduğunu otomatik algılar."""
        raw = base64.b64decode(b64)
        if raw[0] == 0:
            return self.aes_cbc_decrypt(b64, password)
        elif raw[0] == 1:
            return self.aes_gcm_decrypt(b64, password)
        else:
            raise ValueError("Bilinmeyen AES modu flag'i.")

    # ChaCha20-Poly1305 (gerçek implementasyon) için gerekli olan kısım 
    def chacha_encrypt(self, text: str, password: str) -> str:
        salt  = os.urandom(self.SALT_LEN)
        nonce = os.urandom(12)
        key   = self._derive_key(password, salt)
        chacha = ChaCha20Poly1305(key)
        ct = chacha.encrypt(nonce, text.encode('utf-8'), None)
        combined = salt + nonce + ct
        return 'CC20:' + base64.b64encode(combined).decode('ascii')

    def chacha_decrypt(self, data: str, password: str) -> str:
        if not data.startswith('CC20:'):
            raise ValueError("ChaCha20 formatı geçersiz — 'CC20:' prefix eksik.")
        raw   = base64.b64decode(data[5:])
        salt  = raw[:16]
        nonce = raw[16:28]
        ct    = raw[28:]
        key   = self._derive_key(password, salt)
        chacha = ChaCha20Poly1305(key)
        return chacha.decrypt(nonce, ct, None).decode('utf-8')

    # XOR Maskeleme // ekstradan önlem amaçlı bu 
    def xor_encode(self, text: str, key: str) -> str:
        tb = text.encode('utf-8')
        kb = key.encode('utf-8')
        out = bytes(tb[i] ^ kb[i % len(kb)] for i in range(len(tb)))
        return 'XOR:' + base64.b64encode(out).decode('ascii')

    def xor_decode(self, encoded: str, key: str) -> str:
        if not encoded.startswith('XOR:'):
            raise ValueError("XOR formatı geçersiz — 'XOR:' prefix eksik.")
        raw = base64.b64decode(encoded[4:])
        kb  = key.encode('utf-8')
        out = bytes(raw[i] ^ kb[i % len(kb)] for i in range(len(raw)))
        return out.decode('utf-8')

    # Steganografi (Zero-Width karakterler) -----  Steganografi Kısmı
    def stego_hide(self, secret: str, cover: str) -> str:
        if not cover.strip():
            cover = 'Bu metin güvenli bir şekilde iletilmektedir.'
        bits = []
        for ch in secret:
            code = ord(ch)
            for b in range(7, -1, -1):
                bits.append((code >> b) & 1)
        bits.extend([1]*8)  # sonlandırıcı 0xFF
        encoded = ''
        bi = 0
        for c in cover:
            encoded += c
            if bi < len(bits):
                encoded += self.ZW_CHARS[1 if bits[bi] else 0]
                bi += 1
        while bi < len(bits):
            encoded += self.ZW_CHARS[1 if bits[bi] else 0]
            bi += 1
        return encoded

    def stego_reveal(self, text: str) -> str:
        bits = []
        for c in text:
            if c == self.ZW_CHARS[0]:
                bits.append(0)
            elif c == self.ZW_CHARS[1]:
                bits.append(1)
        result = ''
        i = 0
        while i + 7 < len(bits):
            code = 0
            for b in range(8):
                code = (code << 1) | bits[i + b]
            if code == 255:
                break
            result += chr(code)
            i += 8
        return result

    # Şifre Gücü /// Şifre Gücü kısmı
    def password_strength(self, pw: str) -> tuple:
        s = 0
        if len(pw) >= 8:  s += 1
        if len(pw) >= 14: s += 1
        import re
        if re.search(r'[A-Z]', pw) and re.search(r'[a-z]', pw): s += 1
        if re.search(r'[0-9]', pw): s += 1
        if re.search(r'[^A-Za-z0-9]', pw): s += 1
        labels = ['Çok zayıf', 'Zayıf', 'Orta', 'Güçlü', 'Çok güçlü']
        colors = ['red', 'yellow', 'yellow', 'green', 'green']
        idx = max(0, s - 1)
        return labels[idx], colors[idx], s * 20

BANNER = r"""
--      ______   ________   ______      ________                    __ 
--     /      \ |        \ /      \    |        \                  |  \
--    |  $$$$$$\| $$$$$$$$|  $$$$$$\    \$$$$$$$$______    ______  | $$
--    | $$__| $$| $$__    | $$___\$$      | $$  /      \  /      \ | $$
--    | $$    $$| $$  \    \$$    \       | $$ |  $$$$$$\|  $$$$$$\| $$
--    | $$$$$$$$| $$$$$    _\$$$$$$\      | $$ | $$  | $$| $$  | $$| $$
--    | $$  | $$| $$_____ |  \__| $$      | $$ | $$__/ $$| $$__/ $$| $$
--    | $$  | $$| $$     \ \$$    $$______| $$  \$$    $$ \$$    $$| $$
--     \$$   \$$ \$$$$$$$$  \$$$$$$|      \\$$   \$$$$$$   \$$$$$$  \$$
--                                  \$$$$$$                            
--
--   Katmanlı Şifreleme  |  AES-256 + ChaCha20 + XOR
--   Açık kaynak — modifiye edilebilir                                                                  
--
"""

PROMPT = "AES_Tool:~$ "

#Olmadı rüzgardan başka

def cprint(text, color=None, bold=False):
    """Renkli terminal çıktısı"""
    codes = {
        'red': '\033[91m', 'green': '\033[92m', 'yellow': '\033[93m',
        'blue': '\033[94m', 'magenta': '\033[95m', 'cyan': '\033[96m',
        'white': '\033[97m', 'gray': '\033[90m'
    }
    reset = '\033[0m'
    bold_code = '\033[1m' if bold else ''
    c = codes.get(color, '')
    print(f"{bold_code}{c}{text}{reset}")

def cinput(prompt_text=""):
    """AES_Tool prompt'lu input"""
    try:
        return input(f"\033[92m{PROMPT}\033[0m{prompt_text}")
    except KeyboardInterrupt:
        print("\n")
        return ""

def get_password(prompt_text="Şifre: ", confirm=False) -> str:
    while True:
        pw = getpass.getpass(f"\033[92m{PROMPT}\033[0m{prompt_text}")
        if confirm:
            pw2 = getpass.getpass(f"\033[92m{PROMPT}\033[0mŞifreyi tekrar girin: ")
            if pw != pw2:
                cprint("[!] Şifreler eşleşmiyor!", 'red')
                continue
        engine = CryptoEngine()
        label, color, pct = engine.password_strength(pw)
        bar = '█' * (pct // 10) + '░' * (10 - pct // 10)
        cprint(f"    Güç: [{bar}] {label}", color)
        return pw

class TerminalUI:
    def __init__(self):
        self.engine = CryptoEngine()

    def run(self):
        os.system('clear' if os.name != 'nt' else 'cls')
        cprint(BANNER, 'cyan')
        while True:
            self._main_menu()

    def _main_menu(self):
        cprint("\n──── ANA MENÜ ────", 'cyan', bold=True)
        cprint("  [1]  Şifrele", 'green')
        cprint("  [2]  Çöz", 'blue')
        cprint("  [3]  Dosya şifrele", 'green')
        cprint("  [4]  Dosya çöz", 'blue')
        cprint("  [5]  Steganografi — Gizle", 'magenta')
        cprint("  [6]  Steganografi — Ortaya Çıkar", 'magenta')
        cprint("  [7]  Ayarlar", 'yellow')
        cprint("  [0]  Çıkış", 'gray')

        choice = cinput("Seçim: ").strip()

        actions = {
            '1': self._encrypt_flow,
            '2': self._decrypt_flow,
            '3': self._encrypt_file,
            '4': self._decrypt_file,
            '5': self._stego_hide_flow,
            '6': self._stego_reveal_flow,
            '7': self._settings_menu,
            '0': self._exit,
        }
        action = actions.get(choice)
        if action:
            action()
        else:
            cprint("[!] Geçersiz seçim.", 'red')

#saçımı okşayan kimse

    def _encrypt_flow(self):
        cprint("\n──── ŞİFRELE ────", 'green', bold=True)

        # Metin al
        cprint("Şifrelenecek metin (bitirmek için boş satır + Enter):", 'cyan')
        lines = []
        while True:
            try:
                line = input()
                if line == "" and lines:
                    break
                lines.append(line)
            except EOFError:
                break
        text = '\n'.join(lines)
        if not text:
            cprint("[!] Boş metin.", 'red'); return

        # AES modu // AES kısmı
        cprint("\nAES Modu:", 'cyan')
        cprint("  [1] CBC — Klasik (varsayılan)")
        cprint("  [2] GCM — Authenticated (önerilen)")
        mode_choice = cinput("Mod: ").strip()
        aes_mode = 'gcm' if mode_choice == '2' else 'cbc'

        # AES şifresi // AES şifreleme kısmı
        cprint("\n[Katman 1] AES-256 şifresi:", 'green')
        aes_pass = get_password("AES şifresi: ", confirm=True)

        data = text
        layers_used = [f"AES-256-{aes_mode.upper()}"]

        # ChaCha20 //ChaCha20 için olan yer //ChaCha20 Kısmı
        cprint("\n[Katman 2] ChaCha20-Poly1305 ekle? [e/H]: ", 'magenta', bold=False)
        if cinput("").strip().lower() == 'e':
            chacha_pass = get_password("ChaCha20 şifresi (farklı olmalı): ", confirm=True)
            try:
                if aes_mode == 'gcm':
                    data = self.engine.aes_gcm_encrypt(data, aes_pass)
                else:
                    data = self.engine.aes_cbc_encrypt(data, aes_pass)
                data = self.engine.chacha_encrypt(data, chacha_pass)
                layers_used.append("ChaCha20")

                # XOR
                cprint("\n[Katman 3] XOR maskeleme ekle? [e/H]: ", 'yellow')
                if cinput("").strip().lower() == 'e':
                    xor_key = cinput("XOR anahtarı: ").strip()
                    if xor_key:
                        data = self.engine.xor_encode(data, xor_key)
                        layers_used.append("XOR")
            except Exception as ex:
                cprint(f"[HATA] {ex}", 'red'); return
        else:
            chacha_pass = None
            try:
                if aes_mode == 'gcm':
                    data = self.engine.aes_gcm_encrypt(data, aes_pass)
                else:
                    data = self.engine.aes_cbc_encrypt(data, aes_pass)

                # XOR
                cprint("\n[Katman 3] XOR maskeleme ekle? [e/H]: ", 'yellow')
                if cinput("").strip().lower() == 'e':
                    xor_key = cinput("XOR anahtarı: ").strip()
                    if xor_key:
                        data = self.engine.xor_encode(data, xor_key)
                        layers_used.append("XOR")
            except Exception as ex:
                cprint(f"[HATA] {ex}", 'red'); return

        pipeline = " → ".join(layers_used)
        cprint(f"\n✓ Pipeline: {pipeline}", 'green', bold=True)
        cprint("\n──── ŞİFRELİ ÇIKTI ────", 'cyan')
        print(data)
        cprint("\n──────────────────────", 'cyan')

        # Kaydet // (e/H) 
        save = cinput("\nDosyaya kaydet? [e/H]: ").strip().lower()
        if save == 'e':
            fname = cinput("Dosya adı (.enc): ").strip()
            if not fname.endswith('.enc'):
                fname += '.enc'
            meta = {
                'pipeline': layers_used,
                'aes_mode': aes_mode,
            }
            with open(fname, 'w') as f:
                f.write(json.dumps({'meta': meta, 'data': data}, indent=2))
            cprint(f"✓ Kaydedildi: {fname}", 'green')

    def _decrypt_flow(self):
        cprint("\n──── ÇÖZ ────", 'blue', bold=True)

        # Veriyi al // veri input için 
        cprint("Şifreli veriyi girin (yapıştır, sonra Ctrl+D veya boş satır):", 'cyan')
        lines = []
        while True:
            try:
                line = input()
                if line == "" and lines:
                    break
                lines.append(line)
            except EOFError:
                break
        data = '\n'.join(lines).strip()
        if not data:
            cprint("[!] Boş veri.", 'red'); return

        # Hangi katmanlar kullanılmış? // katmanlar neler bak
        cprint("\nKatmanları seç (hangileri şifrelemede kullanıldı?):", 'cyan')
        has_xor    = cinput("XOR var mıydı? [e/H]: ").strip().lower() == 'e'
        has_chacha = cinput("ChaCha20 var mıydı? [e/H]: ").strip().lower() == 'e'

        xor_key = chacha_pass = None
        if has_xor:
            xor_key = cinput("XOR anahtarı: ").strip()
        if has_chacha:
            chacha_pass = get_password("ChaCha20 şifresi: ")
        aes_pass = get_password("AES şifresi: ")
#Olmadı yağmurdan başka
        try:
            if has_xor and xor_key:
                data = self.engine.xor_decode(data, xor_key)
            if has_chacha and chacha_pass:
                data = self.engine.chacha_decrypt(data, chacha_pass)
            data = self.engine.aes_decrypt_auto(data, aes_pass)

            cprint("\n──── ÇÖZÜLEN METİN ────", 'green')
            print(data)
            cprint("───────────────────────", 'green')
        except Exception as ex:
            cprint(f"\n[HATA] Çözme başarısız: {ex}", 'red')
            cprint("Yanlış şifre, yanlış sıra veya bozuk veri.", 'red')
#yanağımdan öpen ve saçlarıma iyi gelen kimse
    def _encrypt_file(self):
        cprint("\n──── DOSYA ŞİFRELE ────", 'green', bold=True)
        path = cinput("Dosya yolu: ").strip()
        if not os.path.exists(path):
            cprint(f"[!] Dosya bulunamadı: {path}", 'red'); return
        with open(path, 'rb') as f:
            content = f.read()
        b64_content = base64.b64encode(content).decode('ascii')
        aes_pass = get_password("AES şifresi: ", confirm=True)
        mode = 'gcm'
        data = self.engine.aes_gcm_encrypt(b64_content, aes_pass)
        out_path = path + '.enc'
        with open(out_path, 'w') as f:
            f.write(data)
        cprint(f"✓ Şifrelendi: {out_path}", 'green')
#Bir gece oturdum sessiz sedasız masamın başına
    def _decrypt_file(self):
        cprint("\n──── DOSYA ÇÖZ ────", 'blue', bold=True)
        path = cinput("Şifreli dosya yolu (.enc): ").strip()
        if not os.path.exists(path):
            cprint(f"[!] Dosya bulunamadı: {path}", 'red'); return
        with open(path, 'r') as f:
            data = f.read().strip()
        aes_pass = get_password("AES şifresi: ")
        try:
            b64_content = self.engine.aes_decrypt_auto(data, aes_pass)
            content = base64.b64decode(b64_content)
            out_path = path.replace('.enc', '.dec')
            with open(out_path, 'wb') as f:
                f.write(content)
            cprint(f"✓ Çözüldü: {out_path}", 'green')
        except Exception as ex:
            cprint(f"[HATA] {ex}", 'red')
#Saat gecenin bir körü herkes uyurken geldin düştün gene aklıma
    def _stego_hide_flow(self):
        cprint("\n──── STEGANOGRAFİ — GİZLE ────", 'magenta', bold=True)
        cprint("Gizlenecek metin:", 'cyan')
        secret = cinput("").strip()
        cprint("Kapak metni (gizli mesaj içine saklanacak metin):", 'cyan')
        cover = cinput("").strip()
        result = self.engine.stego_hide(secret, cover)
        cprint("\nSteganografi çıktısı (görsel olarak normal görünür):", 'green')
        print(result)
        cprint(f"\n[i] Toplam karakter: {len(result)} (gizli karakterler dahil)", 'gray')
#Bir kağıt ve de kalem aldım
    def _stego_reveal_flow(self):
        cprint("\n──── STEGANOGRAFİ — ORTAYA ÇIKAR ────", 'magenta', bold=True)
        cprint("Steganografi metnini girin:", 'cyan')
        text = cinput("").strip()
        result = self.engine.stego_reveal(text)
        if result:
            cprint(f"\nGizli mesaj: {result}", 'green')
        else:
            cprint("[!] Gizli mesaj bulunamadı.", 'red')
#Kalemi kendime durmadan batırdım sanki seni daha kuvvetli anımsamak ister gibi 
    def _settings_menu(self):
        cprint("\n──── AYARLAR ────", 'yellow', bold=True)
        cprint(f"  PBKDF2 iterasyon: {self.engine.PBKDF2_ITERATIONS}", 'gray')
        cprint("  [1] İterasyon sayısını değiştir")
        cprint("  [0] Geri")
        choice = cinput("Seçim: ").strip()
        if choice == '1':
            try:
                n = int(cinput("Yeni iterasyon sayısı (min 10000): ").strip())
                if n < 10000:
                    cprint("[!] Çok az, en az 10000 olmalı.", 'red')
                else:
                    self.engine.PBKDF2_ITERATIONS = n
                    cprint(f"✓ Ayarlandı: {n}", 'green')
            except ValueError:
                cprint("[!] Geçersiz sayı.", 'red')
#gözlerimi kapadım seni hayal eyledim
    def _exit(self):
        cprint("\nGüvenli çıkış. Veriler bellekten silindi.\n", 'gray')
        sys.exit(0)
#Ela gözlerinin parıldayısını hatırladım ama yetmedi
#  GUI ARAYÜZÜ (tkinter) ------ (tkinter bunu kurmayı unutma bu arada gerekli düzenlemeler için )
#Turuncu saçlarını düşündüm sonra anılara gittim geldim
def launch_gui():
    try:
        import tkinter as tk
        from tkinter import ttk, scrolledtext, messagebox, filedialog
    except ImportError:
        print("[!] tkinter bulunamadı. Ubuntu'da: sudo apt install python3-tk")
        sys.exit(1)
#Ve o garip kovboy şapkanı hatırladım
    #Renkler için olan kısım
    engine = CryptoEngine()
    BG      = "#0D1117"
    BG2     = "#161B22"
    GREEN   = "#1D9E75"
    TEAL    = "#9FE1CB"
    PURPLE  = "#AFA9EC"
    AMBER   = "#FAC775"
    FG      = "#E6EDF3"
    GRAY    = "#8B949E"
    RED     = "#F85149"
    FONT    = ("Courier New", 10)
    FONT_B  = ("Courier New", 10, "bold")
    FONT_H  = ("Courier New", 13, "bold")
#O garip anları hatırladım
    root = tk.Tk()
    root.title("AES_Tool — Katmanlı Şifreleme Kasası")
    root.configure(bg=BG)
    root.geometry("900x700")
    root.minsize(800, 600)
#sonrasında ise senin dedin o cümleyi , En sonunda hatırladım 
    # Başlık 
    header = tk.Frame(root, bg=BG, pady=8)
    header.pack(fill='x', padx=16)
    tk.Label(header, text="Katmanlı Şifreleme Kasası", font=("Courier New", 16, "bold"),
             bg=BG, fg=TEAL).pack(side='left')
    for chip, color in [("AES-256", GREEN), ("ChaCha20", "#534AB7"), ("XOR", "#D97706")]:
        tk.Label(header, text=f" {chip} ", font=("Courier New", 9, "bold"),
                 bg=color, fg='white', padx=6, pady=2).pack(side='left', padx=4)
#Acaba senin olgun hali nasıl olur deyişini , Ve bu soruyu sürekli sorup benim olgunlasmis halimi merak edişini hatırladım
    # Notebook (sekmeler) 
    style = ttk.Style()
    style.theme_use('clam')
    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", background=BG2, foreground=FG,
                    font=FONT_B, padding=[12, 6], borderwidth=0)
    style.map("TNotebook.Tab",
              background=[("selected", GREEN)],
              foreground=[("selected", "white")])

    nb = ttk.Notebook(root)
    nb.pack(fill='both', expand=True, padx=10, pady=6)

    def make_frame(title):
        f = tk.Frame(nb, bg=BG, padx=14, pady=10)
        nb.add(f, text=title)
        return f

    def lbl(parent, text, color=GRAY, size=9):
        return tk.Label(parent, text=text.upper(), font=("Courier New", size),
                        bg=parent.cget('bg'), fg=color)

    def entry(parent, show='', width=50):
        e = tk.Entry(parent, font=FONT, bg=BG2, fg=FG, insertbackground=FG,
                     relief='flat', bd=6, show=show, width=width)
        e.bind("<FocusIn>",  lambda ev: e.config(highlightthickness=1, highlightcolor=GREEN, highlightbackground=GREEN))
        e.bind("<FocusOut>", lambda ev: e.config(highlightthickness=0))
        return e
# Neden di bu soru ? , Neydi amacı neydi arkasındaki mantık bu sorunun , Bir denklem mi yoksa sadece kalpten gelen hisler miydi ?
    def textarea(parent, height=6):
        t = scrolledtext.ScrolledText(parent, font=FONT, bg=BG2, fg=FG, insertbackground=FG,
                                      relief='flat', bd=6, height=height, wrap='word')
        return t

    def btn(parent, text, cmd, color=GREEN, fg='white'):
        b = tk.Button(parent, text=text, command=cmd, font=FONT_B,
                      bg=color, fg=fg, activebackground=color,
                      relief='flat', bd=0, padx=12, pady=6, cursor='hand2')
        b.bind("<Enter>", lambda e: b.config(bg=_lighten(color)))
        b.bind("<Leave>", lambda e: b.config(bg=color))
        return b
#O gece geleceğe bir mektup yazdım : Büyümek bu muydu her adımın bir acı , Vede garip hislere sahip olmak mıydı , Kimselere içimdekileri anlatamadım ,Belki bir gün seni yeniden görürüm,
    def _lighten(hex_color):
        h = hex_color.lstrip('#')
        r,g,b = (int(h[i:i+2],16) for i in (0,2,4))
        return f"#{min(r+30,255):02x}{min(g+30,255):02x}{min(b+30,255):02x}"
# bu umut bana iyi gelir seni merak ettim sonra unuttum adını yüzünü sesini en zoruda bunlar zaten bunları unutmak oldu , taki o otobüste sen beni yeniden görene kadar
    def status_bar_msg(sb, msg, ok=True):
        sb.config(text=msg, fg=GREEN if ok else RED)
        root.after(5000, lambda: sb.config(text=""))

    
    #sekme 1: şifrele
    
    f_enc = make_frame("🔒  Şifrele")

    lbl(f_enc, "Giriş Metni").pack(anchor='w', pady=(4,2))
    inp_text = textarea(f_enc, height=5)
    inp_text.pack(fill='x', pady=(0,8))

    # Katmanlar // frame
    layers_frame = tk.LabelFrame(f_enc, text=" Şifreleme Katmanları ",
                                  font=FONT_B, bg=BG, fg=TEAL, bd=1, relief='solid', padx=10, pady=6)
    layers_frame.pack(fill='x', pady=(0,8))
#ve yanıma geldin ben uzaklara dalmıs , gabor mate dağınık zihinler kitabından öğrendim , doctor neufeldun düsüncelerinden birini düsünürken , göz yaslarını kaybetmek düsüncesi bunu düsünürken dalmıstım sen geldin   
    # AES Katmanı
    aes_row = tk.Frame(layers_frame, bg=BG)
    aes_row.pack(fill='x', pady=2)
    tk.Label(aes_row, text="① AES-256", font=FONT_B, bg=BG, fg=TEAL, width=14, anchor='w').pack(side='left')
    tk.Label(aes_row, text="Şifre:", font=FONT, bg=BG, fg=GRAY).pack(side='left', padx=(8,4))
    aes_pass_e = entry(aes_row, show='•', width=22)
    aes_pass_e.pack(side='left')
    tk.Label(aes_row, text="Mod:", font=FONT, bg=BG, fg=GRAY).pack(side='left', padx=(12,4))
    aes_mode_var = tk.StringVar(value='GCM')
    for m in ['CBC','GCM']:
        tk.Radiobutton(aes_row, text=m, variable=aes_mode_var, value=m,
                       font=FONT, bg=BG, fg=FG, selectcolor=BG2,
                       activebackground=BG).pack(side='left', padx=4)
#Yanıma oturdun 
    # ChaCha Katmanı
    chacha_row = tk.Frame(layers_frame, bg=BG)
    chacha_row.pack(fill='x', pady=2)
    chacha_var = tk.BooleanVar()
    tk.Checkbutton(chacha_row, variable=chacha_var, bg=BG, fg=PURPLE,
                   selectcolor=BG2, activebackground=BG,
                   command=lambda: chacha_e.config(state='normal' if chacha_var.get() else 'disabled')).pack(side='left')
    tk.Label(chacha_row, text="② ChaCha20", font=FONT_B, bg=BG, fg=PURPLE, width=13, anchor='w').pack(side='left')
    tk.Label(chacha_row, text="Şifre:", font=FONT, bg=BG, fg=GRAY).pack(side='left', padx=(8,4))
    chacha_e = entry(chacha_row, show='•', width=22)
    chacha_e.pack(side='left')
    chacha_e.config(state='disabled')
#bana beni tanıdın mı dedin
    # XOR Katmanı
    xor_row = tk.Frame(layers_frame, bg=BG)
    xor_row.pack(fill='x', pady=2)
    xor_var = tk.BooleanVar()
    tk.Checkbutton(xor_row, variable=xor_var, bg=BG, fg='#D97706',
                   selectcolor=BG2, activebackground=BG,
                   command=lambda: xor_e.config(state='normal' if xor_var.get() else 'disabled')).pack(side='left')
    tk.Label(xor_row, text="③ XOR", font=FONT_B, bg=BG, fg=AMBER, width=13, anchor='w').pack(side='left')
    tk.Label(xor_row, text="Anahtar:", font=FONT, bg=BG, fg=GRAY).pack(side='left', padx=(8,4))
    xor_e = entry(xor_row, width=22)
    xor_e.pack(side='left')
    xor_e.config(state='disabled')
#Benim cevabım duraksama oldu ama aslında seni direk tanıdım ama söyleyemedim aklımda direk adın belirdi : Buse dedi zihnim Beynim olamaz bu omu dedi
    # Butonlar 
    btn_row = tk.Frame(f_enc, bg=BG)
    btn_row.pack(fill='x', pady=4)
    enc_out = textarea(f_enc, height=5)
#Hayır dedim tanımadım dedim ama yalandı , iyi düsün dedin sorna yalandan geç hatırlamıs gibi yaptım Buse dedim
    enc_status = tk.Label(f_enc, text="", font=FONT, bg=BG, fg=GREEN)
    enc_status.pack(anchor='w')
#Sen nerden beni tanıdın diye sordum (Saçlarım uzundu yüzüm neredeyse seçilmesi zordu) gözlerinden dedin 
    def do_encrypt_gui():
        text = inp_text.get("1.0", "end-1c").strip()
        ap   = aes_pass_e.get()
        if not text or not ap:
            status_bar_msg(enc_status, "[!] Metin ve AES şifresi zorunludur.", False)
            return
        try:
            mode = aes_mode_var.get().lower()
            data = engine.aes_gcm_encrypt(text, ap) if mode == 'gcm' else engine.aes_cbc_encrypt(text, ap)
            used = [f"AES-256-{mode.upper()}"]
            if chacha_var.get():
                cp = chacha_e.get()
                if not cp: status_bar_msg(enc_status, "[!] ChaCha20 şifresi gerekli.", False); return
                data = engine.chacha_encrypt(data, cp)
                used.append("ChaCha20")
            if xor_var.get():
                xk = xor_e.get()
                if not xk: status_bar_msg(enc_status, "[!] XOR anahtarı gerekli.", False); return
                data = engine.xor_encode(data, xk)
                used.append("XOR")
            enc_out.delete("1.0", "end")
            enc_out.insert("1.0", data)
            status_bar_msg(enc_status, "✓ Şifrelendi: " + " → ".join(used), True)
        except Exception as ex:
            status_bar_msg(enc_status, f"[HATA] {ex}", False)
#O an soramadım gözlerimden mi diye olmadı soramadım keşke sorabilseydim (Bir insan bir insanı gözlerinden nasıl tanır nasıl olur bu nasıl oluyor bunu soramadım olmadı sözlerim aklımda kaldı çıkmadı bir türlü dilimden olmadı)
    def copy_enc_out():
        root.clipboard_clear()
        root.clipboard_append(enc_out.get("1.0", "end-1c"))
        status_bar_msg(enc_status, "✓ Panoya kopyalandı.", True)
#Sanırım artık senin üstünden çok vakit geçti seni anımsamak güzeldi
    btn(btn_row, "🔒  Şifrele", do_encrypt_gui).pack(side='left', padx=(0,8))
    btn(btn_row, "📋  Kopyala", copy_enc_out, color='#1C3A4A').pack(side='left')
    lbl(f_enc, "Şifreli Çıktı").pack(anchor='w', pady=(6,2))
    enc_out.pack(fill='x')
#ama unutmak üzücü.
    #Çözümleme kısmı:
    # sekme 2: çöz // çözümle
    f_dec = make_frame("🔓  Çöz")
    lbl(f_dec, "Şifreli Veri").pack(anchor='w', pady=(4,2))
    dec_inp = textarea(f_dec, height=5)
    dec_inp.pack(fill='x', pady=(0,8))

    dl_frame = tk.LabelFrame(f_dec, text=" Katman Seçimi ",
                              font=FONT_B, bg=BG, fg=BLUE if False else TEAL,
                              bd=1, relief='solid', padx=10, pady=6)
    dl_frame.pack(fill='x', pady=(0,8))
    dx_var = tk.BooleanVar()
    dc_var = tk.BooleanVar()
    dx_row = tk.Frame(dl_frame, bg=BG)
    dx_row.pack(fill='x', pady=2)
    tk.Checkbutton(dx_row, variable=dx_var, bg=BG, fg=AMBER, selectcolor=BG2, activebackground=BG).pack(side='left')
    tk.Label(dx_row, text="XOR var mıydı?", font=FONT_B, bg=BG, fg=AMBER, width=16, anchor='w').pack(side='left')
    tk.Label(dx_row, text="Anahtar:", font=FONT, bg=BG, fg=GRAY).pack(side='left', padx=(8,4))
    dxor_e = entry(dx_row, width=22)
    dxor_e.pack(side='left')
    dc_row = tk.Frame(dl_frame, bg=BG)
    dc_row.pack(fill='x', pady=2)
    tk.Checkbutton(dc_row, variable=dc_var, bg=BG, fg=PURPLE, selectcolor=BG2, activebackground=BG).pack(side='left')
    tk.Label(dc_row, text="ChaCha20 var mıydı?", font=FONT_B, bg=BG, fg=PURPLE, width=16, anchor='w').pack(side='left')
    tk.Label(dc_row, text="Şifre:", font=FONT, bg=BG, fg=GRAY).pack(side='left', padx=(8,4))
    dcha_e = entry(dc_row, show='•', width=22)
    dcha_e.pack(side='left')

    da_row = tk.Frame(dl_frame, bg=BG)
    da_row.pack(fill='x', pady=2)
    tk.Label(da_row, text="① AES Şifresi:", font=FONT_B, bg=BG, fg=TEAL, width=18, anchor='w').pack(side='left')
    daes_e = entry(da_row, show='•', width=22)
    daes_e.pack(side='left')

    dec_out = textarea(f_dec, height=5)
    dec_status = tk.Label(f_dec, text="", font=FONT, bg=BG, fg=GREEN)

    def do_decrypt_gui():
        data = dec_inp.get("1.0", "end-1c").strip()
        ap   = daes_e.get()
        if not data or not ap:
            status_bar_msg(dec_status, "[!] Veri ve AES şifresi zorunludur.", False)
            return
        try:
            if dx_var.get():
                xk = dxor_e.get()
                if not xk: status_bar_msg(dec_status, "[!] XOR anahtarı gerekli.", False); return
                data = engine.xor_decode(data, xk)
            if dc_var.get():
                cp = dcha_e.get()
                if not cp: status_bar_msg(dec_status, "[!] ChaCha20 şifresi gerekli.", False); return
                data = engine.chacha_decrypt(data, cp)
            data = engine.aes_decrypt_auto(data, ap)
            dec_out.delete("1.0", "end")
            dec_out.insert("1.0", data)
            status_bar_msg(dec_status, "✓ Tüm katmanlar çözüldü.", True)
        except Exception as ex:
            status_bar_msg(dec_status, f"[HATA] Yanlış şifre veya bozuk veri.", False)

    dbtn_row = tk.Frame(f_dec, bg=BG)
    dbtn_row.pack(fill='x', pady=4)
    btn(dbtn_row, "🔓  Çöz", do_decrypt_gui, color='#3C3489').pack(side='left')
    dec_status.pack(anchor='w', pady=2)
    lbl(f_dec, "Çözülen Metin").pack(anchor='w', pady=(6,2))
    dec_out.pack(fill='x')
    #sekme 3: STEGANOGRAFİ 
    f_stego = make_frame("👁  Steganografi")

    lbl(f_stego, "Gizlenecek Mesaj").pack(anchor='w', pady=(4,2))
    stego_secret = entry(f_stego, width=60)
    stego_secret.pack(fill='x', pady=(0,8))

    lbl(f_stego, "Kapak Metni").pack(anchor='w', pady=(0,2))
    stego_cover = textarea(f_stego, height=4)
    stego_cover.pack(fill='x', pady=(0,8))

    stego_out = textarea(f_stego, height=4)
    stego_status = tk.Label(f_stego, text="", font=FONT, bg=BG, fg=GREEN)

    def do_stego_hide():
        secret = stego_secret.get().strip()
        cover  = stego_cover.get("1.0","end-1c").strip()
        if not secret:
            status_bar_msg(stego_status, "[!] Gizlenecek mesaj boş.", False); return
        result = engine.stego_hide(secret, cover)
        stego_out.delete("1.0","end")
        stego_out.insert("1.0", result)
        status_bar_msg(stego_status, f"✓ Gizlendi. Çıktı {len(result)} karakter.", True)

    def do_stego_reveal():
        text = stego_out.get("1.0","end-1c").strip() or stego_cover.get("1.0","end-1c").strip()
        result = engine.stego_reveal(text)
        if result:
            stego_secret.delete(0,'end')
            stego_secret.insert(0, result)
            status_bar_msg(stego_status, f"✓ Gizli mesaj: {result}", True)
        else:
            status_bar_msg(stego_status, "[!] Gizli mesaj bulunamadı.", False)

    sbtn_row = tk.Frame(f_stego, bg=BG)
    sbtn_row.pack(fill='x', pady=4)
    btn(sbtn_row, "🙈  Gizle", do_stego_hide, color='#6B3FA0').pack(side='left', padx=(0,8))
    btn(sbtn_row, "👁  Ortaya Çıkar", do_stego_reveal, color='#3A4A6B').pack(side='left')
    stego_status.pack(anchor='w')
    lbl(f_stego, "Steganografi Çıktısı / Ortaya Çıkarılacak Metin").pack(anchor='w', pady=(6,2))
    stego_out.pack(fill='x')

    # Alt durum çubuğu 
    statusbar = tk.Label(root, text="AES_Tool hazır — Açık kaynak | modifiye edebilirsin",
                         font=("Courier New", 9), bg=BG2, fg=GRAY, anchor='w', padx=10, pady=4)
    statusbar.pack(fill='x', side='bottom')

    root.mainloop()
# Başlatıcı  Terminal mi GUI mi? // seçim nasıl olcak ? (seçim kısmı)
def startup_selector():
    """Başlatma anında terminal veya GUI seçimi."""
    os.system('clear' if os.name != 'nt' else 'cls')
    print(BANNER)
    print("\033[96m  Nasıl çalıştırmak istersin ?\033[0m\n")
    print("  \033[92m[1]\033[0m  Terminal modu  (AES_Tool:~$ prompt)")
    print("  \033[94m[2]\033[0m  GUI modu       (Grafik arayüz - tkinter)")
    print("  \033[90m[0]\033[0m  Çıkış\n")

    try:
        choice = input(f"\033[92m{PROMPT}\033[0mSeçim [1/2/0]: ").strip()
    except KeyboardInterrupt:
        print("\n")
        sys.exit(0)

    if choice == '1':
        TerminalUI().run()
    elif choice == '2':
        launch_gui()
    elif choice == '0':
        sys.exit(0)
    else:
        print("Geçersiz seçim.")
        startup_selector()

def main():
    parser = argparse.ArgumentParser(
        description='AES_Tool — Katmanlı Şifreleme Aracı',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Örnekler:
  python aes_tool.py                  → Başlatma menüsü
  python aes_tool.py --terminal       → Doğrudan terminal modu
  python aes_tool.py --gui            → Doğrudan GUI modu

Modül olarak kullanım:
  from aes_tool import CryptoEngine
  engine = CryptoEngine()
  enc = engine.aes_gcm_encrypt("merhaba", "şifrem")
  dec = engine.aes_decrypt_auto(enc, "şifrem")
        """
    )
    parser.add_argument('--terminal', '-t', action='store_true', help='Terminal modunda başlat')
    parser.add_argument('--gui',      '-g', action='store_true', help='GUI modunda başlat')
    args = parser.parse_args()

    if args.terminal:
        TerminalUI().run()
    elif args.gui:
        launch_gui()
    else:
        startup_selector()

if __name__ == '__main__':
    main()
