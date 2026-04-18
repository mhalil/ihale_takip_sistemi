import sys
import os
import sqlite3
import shutil
import csv
from datetime import datetime, timedelta

from PySide6 import QtWidgets
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                QHBoxLayout, QTableWidget, QTableWidgetItem, 
                                QPushButton, QLineEdit, QLabel, QDialog, 
                                QCheckBox, QDialogButtonBox, QHeaderView, QFrame,
                                QTabWidget, QScrollArea, QComboBox, QListView,  
                                QMessageBox, QDateEdit, QGraphicsDropShadowEffect, QGridLayout, 
                                QSplitter, QCalendarWidget, QStyledItemDelegate, QStyle,
                                QFileDialog
                                )
from PySide6.QtCore import Qt, QDate, QRegularExpression, QSettings
from PySide6.QtGui import (QIntValidator, QRegularExpressionValidator, QFont, 
                            QColor,  QTextCharFormat, QBrush, QPainter)

# --- MODERN UI CONFIG ---
class DropdownDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        # Seçili veya hover durumunda özel çizim
        if option.state & (QStyle.StateFlag.State_Selected | QStyle.StateFlag.State_MouseOver):
            painter.save()
            # Indigo arka plan
            painter.setBrush(QColor("#6366f1"))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRect(option.rect)
            # Beyaz metin
            painter.setPen(QColor("white"))
            font = option.font
            font.setBold(True)
            painter.setFont(font)
            # Metni merkeze hizala (padding ile)
            text_rect = option.rect.adjusted(10, 0, -10, 0)
            painter.drawText(text_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, index.data())
            painter.restore()
        else:
            super().paint(painter, option, index)

COMMON_STYLE = """
QTabWidget::pane { border: none; background: transparent; }
QTabBar::tab { padding: 10px 20px; border-top-left-radius: 8px; border-top-right-radius: 8px; margin-right: 2px; font-weight: bold; }
QPushButton { border-radius: 6px; padding: 8px 16px; font-weight: bold; border: none; }
QLineEdit, QComboBox, QDateEdit { border-radius: 6px; padding: 8px; }
QTableWidget { border-radius: 8px; }
QHeaderView::section { padding: 10px; border: none; font-weight: bold; }
QScrollBar:vertical { border: none; width: 10px; margin: 0px; }
QScrollBar::handle:vertical { min-height: 20px; border-radius: 5px; }
"""

LIGHT_STYLE = COMMON_STYLE + """
QMainWindow { background-color: #f1f5f9; }
QTabBar::tab { background: #cbd5e1; color: #475569; }
QTabBar::tab:selected { background: #6366f1; color: white; }
QPushButton { background-color: #6366f1; color: white; }
QPushButton:hover { background-color: #4f46e5; }
QPushButton#SecondaryBtn { background-color: #94a3b8; }
QPushButton#SecondaryBtn:hover { background-color: #64748b; }
QPushButton#DangerBtn { background-color: #ef4444; }
QPushButton#DangerBtn:hover { background-color: #dc2626; }
QPushButton#SuccessBtn { background-color: #22c55e; }
QPushButton#SuccessBtn:hover { background-color: #16a34a; }
QPushButton#PrimaryBtn { background-color: #6366f1; color: white; }
QPushButton#PrimaryBtn:hover { background-color: #4f46e5; }
QPushButton#WarningBtn { background-color: #f59e0b; color: white; }
QPushButton#WarningBtn:hover { background-color: #d97706; }
QPushButton#InfoBtn { background-color: #CDAB8F; color: white; }
QPushButton#InfoBtn:hover { background-color: #986A44; }
QLineEdit, QComboBox, QDateEdit { background-color: white; border: 1px solid #94a3b8; color: #1e293b; }
QTableWidget { background-color: white; border: 1px solid #cbd5e1; gridline-color: #e2e8f0; color: #1e293b; alternate-background-color: #eff6ff; }
QHeaderView::section { background-color: #e2e8f0; color: #475569; }
QScrollBar:vertical { background: #e2e8f0; }
QScrollBar::handle:vertical { background: #94a3b8; }
QScrollArea, QScrollArea QWidget { background-color: #f1f5f9; border: none; }
"""

DARK_STYLE = COMMON_STYLE + """
QMainWindow, QDialog { background-color: #0f172a; }
QTabBar::tab { background: #1e293b; color: #94a3b8; }
QTabBar::tab:selected { background: #6366f1; color: white; }
QPushButton { background-color: #6366f1; color: white; }
QPushButton:hover { background-color: #4f46e5; }
QPushButton#SecondaryBtn { background-color: #334155; }
QPushButton#SecondaryBtn:hover { background-color: #475569; }
QPushButton#DangerBtn { background-color: #991b1b; }
QPushButton#DangerBtn:hover { background-color: #ef4444; }
QPushButton#SuccessBtn { background-color: #16a34a; }
QPushButton#SuccessBtn:hover { background-color: #22c55e; }
QPushButton#PrimaryBtn { background-color: #6366f1; color: white; }
QPushButton#PrimaryBtn:hover { background-color: #4f46e5; }
QPushButton#WarningBtn { background-color: #f59e0b; color: white; }
QPushButton#WarningBtn:hover { background-color: #d97706; }
QPushButton#InfoBtn { background-color: #CDAB8F; color: white; }
QPushButton#InfoBtn:hover { background-color: #986A44; }
QLineEdit, QComboBox, QDateEdit, QTextEdit { background-color: #1e293b; border: 1px solid #334155; color: #f8fafc; }
QComboBox QAbstractItemView {background-color: #1e293b; color: #f8fafc; selection-background-color: #6366f1; selection-color: white; border: 1px solid #334155; outline: none; }
QTableWidget { background-color: #1e293b; border: 1px solid #334155; gridline-color: #0f172a; color: #f8fafc; alternate-background-color: #2d3d5a; }
QHeaderView::section { background-color: #334155; color: #94a3b8; }
QScrollBar:vertical { background: #1e293b; }
QScrollBar::handle:vertical { background: #475569; }
QLabel, QCheckBox { color: #f8fafc; }
QCheckBox::indicator { width: 20px; height: 20px; border: 2px solid #334155; border-radius: 4px; background: #1e293b; }
QCheckBox::indicator:checked { background-color: #6366f1; border-color: #6366f1; }
QCheckBox::indicator:indeterminate { background-color: #94a3b8; border-color: #94a3b8; }
QCheckBox::indicator:unchecked:hover { border-color: #6366f1; }
QScrollArea, QScrollArea QWidget { background-color: #0f172a; border: none; }
QTreeWidget { background-color: #1e293b; border: 1px solid #334155; color: #f8fafc; outline: none; }
QTreeWidget::item { padding: 4px; }
QTreeWidget::item:selected { background-color: #6366f1; color: white; }
QTreeWidget::item:hover { background-color: #2d3d5a; }
"""

# --- GLOBAL CONFIG ---
COLUMN_MAPPING = {
    "Ambar Teslimi Gerçekleşti": "Ambar teslimi gerceklesti",
    "Testler Başladı": "Testler basladi",
    "Test Sonuçları Geldi": "Test sonuclari geldi",
    "Kabul Raporu imzada": "Muayene - Kabul  Evragi imzada",
    "Kabul Yapıldı": "Kabul Yapildi",
    "Heyet Başkanına Haber Verildi": "Heyet Baskanina Haber Verildi",
    "Ödeme Belgesi Oluşturuldu": "Odeme Emri Hazirlandi"
}

# --- LOGIN DIALOG ---
class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("İhale Takip Sistemi - Giriş")
        self.setFixedWidth(350)
        self.settings = QSettings("IhaleSystem", "LoginSettings")
        self.setup_ui()
        self.load_settings()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel("Hoş Geldiniz")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #6366f1; margin-bottom: 10px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        layout.addWidget(QLabel("<b>Kullanıcı Adı:</b>"))
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Kullanıcı adınızı girin")
        layout.addWidget(self.username_input)

        layout.addWidget(QLabel("<b>Şifre:</b>"))
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Şifrenizi girin")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input)

        self.remember_me = QCheckBox("Beni Hatırla")
        self.auto_login = QCheckBox("Otomatik Giriş")
        
        check_layout = QHBoxLayout()
        check_layout.addWidget(self.remember_me)
        check_layout.addWidget(self.auto_login)
        layout.addLayout(check_layout)

        self.login_btn = QPushButton("Giriş Yap")
        self.login_btn.setMinimumHeight(40)
        self.login_btn.clicked.connect(self.handle_login)
        layout.addWidget(self.login_btn)

        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #ef4444; font-size: 11px;")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

    def load_settings(self):
        saved_user = self.settings.value("username", "")
        saved_pass = self.settings.value("password", "")
        is_remember = self.settings.value("remember", "false") == "true"
        is_auto = self.settings.value("auto_login", "false") == "true"

        if saved_user:
            self.username_input.setText(saved_user)
            if is_remember:
                self.password_input.setText(saved_pass)
                self.remember_me.setChecked(True)
            
            if is_auto:
                self.auto_login.setChecked(True)
                # If auto-login is on, we'll trigger it shortly after window shows
                # but handle_login needs to be called after the dialog is ready

    def handle_login(self):
        username = self.username_input.text()
        password = self.password_input.text()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            global CURRENT_USER, CURRENT_USER_ROLE
            CURRENT_USER = username
            # user structure: username, password, role (index 2)
            # Safe check if column exists, otherwise default to user/admin check
            if len(user) > 2:
                CURRENT_USER_ROLE = user[2]
            else:
                 # Fallback for old schema if migration failed or legacy
                 CURRENT_USER_ROLE = "admin" if username == "admin" else "user"
            
            # Save settings
            self.settings.setValue("username", username)
            if self.remember_me.isChecked():
                self.settings.setValue("password", password)
                self.settings.setValue("remember", "true")
            else:
                self.settings.setValue("password", "")
                self.settings.setValue("remember", "false")
            
            if self.auto_login.isChecked():
                self.settings.setValue("auto_login", "true")
            else:
                self.settings.setValue("auto_login", "false")

            self.accept()
        else:
            self.status_label.setText("Hatalı kullanıcı adı veya şifre!")

# --- USER MANAGEMENT DIALOG ---
class UserManagementDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Kullanıcı İşlemleri")
        self.setFixedWidth(450)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        # Tab widget for different actions
        tabs = QTabWidget()
        
        # Tab 1: Password Change
        pw_tab = QWidget()
        pw_layout = QVBoxLayout(pw_tab)
        
        pw_layout.addWidget(QLabel(f"<b>Kullanıcı:</b> {CURRENT_USER}"))
        
        self.new_pw = QLineEdit()
        self.new_pw.setPlaceholderText("Yeni Şifre")
        self.new_pw.setEchoMode(QLineEdit.EchoMode.Password)
        pw_layout.addWidget(QLabel("Yeni Şifre:"))
        pw_layout.addWidget(self.new_pw)
        
        self.confirm_pw = QLineEdit()
        self.confirm_pw.setPlaceholderText("Yeni Şifre (Tekrar)")
        self.confirm_pw.setEchoMode(QLineEdit.EchoMode.Password)
        pw_layout.addWidget(QLabel("Yeni Şifre (Tekrar):"))
        pw_layout.addWidget(self.confirm_pw)
        
        btn_change = QPushButton("Şifreyi Güncelle")
        btn_change.clicked.connect(self.handle_pw_change)
        pw_layout.addWidget(btn_change)
        pw_layout.addStretch()
        
        tabs.addTab(pw_tab, "Şifre Değiştir")
        
        # Add User (Admin Only)
        if CURRENT_USER_ROLE == "admin":
            add_tab = QWidget()
            add_layout = QVBoxLayout(add_tab)
            
            self.new_username = QLineEdit()
            self.new_username.setPlaceholderText("Yeni Kullanıcı Adı")
            add_layout.addWidget(QLabel("Kullanıcı Adı:"))
            add_layout.addWidget(self.new_username)
            
            self.new_user_pw = QLineEdit()
            self.new_user_pw.setPlaceholderText("Şifre")
            self.new_user_pw.setEchoMode(QLineEdit.EchoMode.Password)
            add_layout.addWidget(QLabel("Şifre:"))
            add_layout.addWidget(self.new_user_pw)

            self.new_user_pw_confirm = QLineEdit()
            self.new_user_pw_confirm.setPlaceholderText("Şifre (Tekrar)")
            self.new_user_pw_confirm.setEchoMode(QLineEdit.EchoMode.Password)
            add_layout.addWidget(QLabel("Şifre (Tekrar):"))
            add_layout.addWidget(self.new_user_pw_confirm)
            
            self.admin_check = QCheckBox("Yönetici (Admin) Yetkisi Ver")
            add_layout.addWidget(self.admin_check)
            
            btn_add = QPushButton("Kullanıcı Ekle")
            btn_add.clicked.connect(self.handle_add_user)
            add_layout.addWidget(btn_add)
            
            add_layout.addWidget(QLabel("<b>Mevcut Kullanıcılar:</b>"))
            self.user_list = QLabel()
            self.user_list.setWordWrap(True)
            self.user_list.setTextFormat(Qt.TextFormat.RichText)
            add_layout.addWidget(self.user_list)
            
            add_layout.addStretch()
            tabs.addTab(add_tab, "Kullanıcı Ekle")

            # Tab 3: Role Management (Admin Only)
            role_tab = QWidget()
            role_layout = QVBoxLayout(role_tab)
            
            role_layout.addWidget(QLabel("<b>Kullanıcı Yetkilerini Düzenle</b>"))
            
            self.role_user_combo = QComboBox()
            self.role_user_combo.setView(QListView())
            self.role_user_combo.setItemDelegate(DropdownDelegate())
            self.role_user_combo.currentIndexChanged.connect(self.on_role_user_selected)
            role_layout.addWidget(QLabel("Kullanıcı Seç:"))
            role_layout.addWidget(self.role_user_combo)
            
            self.role_admin_check = QCheckBox("Yönetici (Admin) Yetkisi")
            role_layout.addWidget(self.role_admin_check)
            
            btn_update_role = QPushButton("Yetkiyi Güncelle")
            btn_update_role.clicked.connect(self.handle_role_update)
            role_layout.addWidget(btn_update_role)
            
            role_layout.addStretch()
            tabs.addTab(role_tab, "Rol Yönetimi")
            
            # Load users for role mgmt
            self.refresh_role_combo()
            self.update_user_list_display()
            
        layout.addWidget(tabs)
        
        close_btn = QPushButton("Kapat")
        close_btn.clicked.connect(self.reject)
        layout.addWidget(close_btn)

    def handle_pw_change(self):
        pw1 = self.new_pw.text()
        pw2 = self.confirm_pw.text()
        
        if not pw1:
            QMessageBox.warning(self, "Hata", "Şifre boş olamaz!")
            return
        if pw1 != pw2:
            QMessageBox.warning(self, "Hata", "Şifreler uyuşmuyor!")
            return
            
        update_password(CURRENT_USER, pw1)
        log_action("Şifre Değiştirme", f"Kullanıcı: {CURRENT_USER}")
        QMessageBox.information(self, "Başarılı", "Şifreniz güncellendi.")
        self.new_pw.clear()
        self.confirm_pw.clear()

    def handle_add_user(self):
        name = self.new_username.text()
        pw = self.new_user_pw.text()
        pw_confirm = self.new_user_pw_confirm.text()
        role = "admin" if self.admin_check.isChecked() else "user"
        
        if not name or not pw:
            QMessageBox.warning(self, "Hata", "Kullanıcı adı ve şifre gereklidir!")
            return
            
        if pw != pw_confirm:
            QMessageBox.warning(self, "Hata", "Şifreler uyuşmuyor!")
            return
            
        if add_user(name, pw, role):
            log_action("Kullanıcı Ekleme", f"Yeni Kullanıcı: {name}, Rol: {role}")
            QMessageBox.information(self, "Başarılı", f"'{name}' kullanıcısı ({role}) eklendi.")
            self.new_username.clear()
            self.new_user_pw.clear()
            self.new_user_pw_confirm.clear()
            self.admin_check.setChecked(False)
            self.update_user_list_display()
            self.refresh_role_combo()
        else:
            QMessageBox.warning(self, "Hata", "Bu kullanıcı adı zaten mevcut olabilir.")

    def refresh_role_combo(self):
        self.role_user_combo.blockSignals(True)
        self.role_user_combo.clear()
        self.users_data = fetch_users_raw() # list of (username, role)
        for u, r in self.users_data:
            self.role_user_combo.addItem(f"{u} ({r})", userData=(u, r))
        self.role_user_combo.blockSignals(False)
        self.on_role_user_selected()

    def update_user_list_display(self):
        users_raw = fetch_users_raw()
        admins = sorted([u for u, r in users_raw if r == "admin"])
        users = sorted([u for u, r in users_raw if r != "admin"])
        
        html = ""
        if admins:
            html += "<b>Yöneticiler (Admin):</b><br>" + ", ".join(admins) + "<br><br>"
        
        if users:
            html += "<b>Kullanıcılar (User):</b><br>" + ", ".join(users)
            
        self.user_list.setText(html)

    def on_role_user_selected(self):
        data = self.role_user_combo.currentData()
        if data:
            username, role = data
            self.role_admin_check.setChecked(role == "admin")
            self.role_admin_check.setEnabled(username != "admin") # Protect main admin

    def handle_role_update(self):
        data = self.role_user_combo.currentData()
        if not data: return
        
        username, old_role = data
        new_role = "admin" if self.role_admin_check.isChecked() else "user"
        
        if username == "admin" and new_role != "admin":
             QMessageBox.warning(self, "Hata", "Ana 'admin' kullanıcısının yetkisi alınamaz!")
             self.role_admin_check.setChecked(True)
             return
             
        update_user_role(username, new_role)
        log_action("Yetki Güncelleme", f"Kullanıcı: {username}, Yeni Rol: {new_role}")
        QMessageBox.information(self, "Başarılı", f"'{username}' için yetki güncellendi.")
        
        # Refresh lists
        self.update_user_list_display()
        self.refresh_role_combo()

# --- CUSTOM WIDGETS ---
class SortableTableWidgetItem(QTableWidgetItem):
    def __lt__(self, other):
        # Özel sıralama anahtarı (UserRole) varsa ona göre sırala
        v1 = self.data(Qt.ItemDataRole.UserRole)
        v2 = other.data(Qt.ItemDataRole.UserRole)
        if v1 is not None and v2 is not None:
            return v1 < v2
        # Yoksa standart metin sıralaması
        return super().__lt__(other)


# --- TÜRKÇE ALFABETİK SIRALAMA ---
_TR_ALPHABET = "abcçdefgğhıijklmnoöprsştuüvyz"
_TR_ORDER = {ch: i for i, ch in enumerate(_TR_ALPHABET)}

def tr_key(text):
    """Türkçe karakterleri doğru sıralayan anahtar fonksiyonu."""
    text = str(text).lower()
    return [_TR_ORDER.get(ch, len(_TR_ALPHABET) + ord(ch)) for ch in text]

def get_date_color(date_str, is_completed):
    if not date_str or is_completed:
        return None
    try:
        target_date = datetime.strptime(date_str[:10], "%Y-%m-%d").date()
        today = datetime.now().date()
        if target_date < today:
            return "#ef4444" # Kırmızı (Gecikmiş)
        if target_date <= today + timedelta(days=7):
            return "#f59e0b" # Turuncu (Yaklaşıyor)
    except:
        pass
    return None

# --- YEDEKLEME FONKSİYONLARI ---
def check_and_create_backup():
    try:
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
        else:
            base_path = os.path.dirname(os.path.abspath(__file__))
            
        db_path = os.path.join(base_path, 'veriler.db')
        backup_dir = os.path.join(base_path, 'Yedekler')
        
        # Eğer veritabanı yoksa yedeklenecek bir şey de yoktur
        if not os.path.exists(db_path):
            return
            
        # Yedekler klasörü yoksa oluştur
        os.makedirs(backup_dir, exist_ok=True)
        
        # Mevcut yedekleri bul
        backups = [f for f in os.listdir(backup_dir) if f.startswith('veriler_yedek_') and f.endswith('.db')]
        
        needs_backup = False
        
        if not backups:
            needs_backup = True
        else:
            # En son yedeğin tarihini bul
            latest_time = None
            for backup in backups:
                try:
                    # Dosya isminden tarihi çıkar (veriler_yedek_YYYY-MM-DD_HH-MM-SS.db)
                    time_str = backup.replace("veriler_yedek_", "").replace(".db", "")
                    backup_dt = datetime.strptime(time_str, "%Y-%m-%d_%H-%M-%S")
                    if latest_time is None or backup_dt > latest_time:
                        latest_time = backup_dt
                except ValueError:
                    # Eski format veya isimlendirme varsa dosya değiştirilme tarihine bak
                    backup_path = os.path.join(backup_dir, backup)
                    mtime = os.path.getmtime(backup_path)
                    mtime_dt = datetime.fromtimestamp(mtime)
                    if latest_time is None or mtime_dt > latest_time:
                        latest_time = mtime_dt
            
            # 7 gün (1 hafta) geçmiş mi kontrol et
            if latest_time:
                time_diff = datetime.now() - latest_time
                if time_diff >= timedelta(days=7):
                    needs_backup = True
            else:
                needs_backup = True
                
        if needs_backup:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            backup_file = os.path.join(backup_dir, f"veriler_yedek_{timestamp}.db")
            shutil.copy(db_path, backup_file)
            print(f"Yedek alındı: {backup_file}")
            
    except Exception as e:
        print(f"Yedekleme hatası: {e}")

# --- VERİ TABANI FONKSİYONLARI ---
def get_db_connection():
    # Determine the directory of the executable or script
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
        
    db_path = os.path.join(base_path, 'veriler.db')
    conn = sqlite3.connect(db_path, check_same_thread=False)
    cursor = conn.cursor()
    
    # Yeni sütunu ekleme (Eğer yoksa)
    try:
        cursor.execute("SELECT `Parti Miktari` FROM data LIMIT 1")
    except sqlite3.OperationalError:
        try:
            cursor.execute("ALTER TABLE data ADD COLUMN `Parti Miktari` TEXT")
            conn.commit()
        except:
            pass
            
    # Sözleşme Tarihi sütunu ekleme (Eğer yoksa)
    try:
        cursor.execute("SELECT `Sozlesme Tarihi` FROM data LIMIT 1")
    except sqlite3.OperationalError:
        try:
            cursor.execute("ALTER TABLE data ADD COLUMN `Sozlesme Tarihi` TEXT")
            conn.commit()
        except:
            pass

    # ## Malzeme Detayi sütunu ekleme (Eğer yoksa)
    # #try:
        # #cursor.execute("SELECT `Malzeme Detayi` FROM data LIMIT 1")
    # #except sqlite3.OperationalError:
        # #try:
            # #cursor.execute("ALTER TABLE data ADD COLUMN `Malzeme Detayi` TEXT")
            # #conn.commit()
        # #except:
            # #pass

    # ## Tek seferlik: Aciklama -> Malzeme Detayi veri kopyalama
    # #try:
        # #cursor.execute("""
            # #UPDATE data SET `Malzeme Detayi` = `Aciklama`
            # #WHERE (`Malzeme Detayi` IS NULL OR `Malzeme Detayi` = '')
            # #AND (`Aciklama` IS NOT NULL AND `Aciklama` != '')
        # #""")
        # #conn.commit()
    # #except:
        # #pass
            
    # Heyet Başkanına Haber Verildi sütunu ekleme (Eğer yoksa)
    try:
        cursor.execute("SELECT `Heyet Baskanina Haber Verildi` FROM data LIMIT 1")
    except sqlite3.OperationalError:
        try:
            cursor.execute("ALTER TABLE data ADD COLUMN `Heyet Baskanina Haber Verildi` REAL DEFAULT 0.0")
            conn.commit()
        except:
            pass

    # Ensure users table exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)
    # Add default admin user if no users exist
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("admin", "admin", "admin"))
    
    # Ensure logs table exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            user TEXT,
            action TEXT,
            details TEXT
        )
    """)
    conn.commit()
    return conn

def log_action(action, details=""):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO logs (timestamp, user, action, details) VALUES (?, ?, ?, ?)",
                       (timestamp, CURRENT_USER, action, details))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Log error: {e}")

def fetch_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, role FROM users")
    users = [f"{r[0]} ({r[1]})" for r in cursor.fetchall()]
    conn.close()
    return users

def fetch_users_raw():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, role FROM users")
    users = cursor.fetchall()
    conn.close()
    return users

def update_user_role(username, new_role):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET role = ? WHERE username = ?", (new_role, username))
    conn.commit()
    conn.close()

def add_user(username, password, role="user"):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
        conn.commit()
        conn.close()
        return True
    except:
        return False

def update_password(username, new_password):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, username))
    conn.commit()
    conn.close()

# Global session user
CURRENT_USER = None
CURRENT_USER_ROLE = "user"

# --- YARDIMCI FONKSİYONLAR (PARA BİRİMİ) ---
def format_money(value):
    if value is None:
        return "0,00"
    try:
        # Önce standart format (örn: 1,234.56)
        formatted = f"{float(value):,.2f}"
        # Sonra nokta/virgül değişimi (örn: 1.234,56)
        return formatted.replace(',', 'X').replace('.', ',').replace('X', '.')
    except:
        return "0,00"

def parse_money(text):
    if text is None:
        return 0.0
    if isinstance(text, (int, float)):
        return float(text)
    try:
        # Eğer string ise: Noktaları sil (binlik), virgülü noktaya çevir (ondalık)
        text_str = str(text).strip()
        if not text_str:
            return 0.0
        # "1.234,56" -> "1234.56"
        # Ama eğer string "1234.56" formatındaysa (nokta ondalık ise):
        if ',' in text_str and '.' in text_str:
            # Hem nokta hem virgül varsa: Nokta binlik, virgül ondalıktır (TR format)
            clean_text = text_str.replace('.', '').replace(',', '.')
        elif ',' in text_str:
            # Sadece virgül varsa: Ondalık ayracıdır
            clean_text = text_str.replace(',', '.')
        elif '.' in text_str:
            # Sadece nokta varsa: son segmentin uzunluğuna göre karar ver
            # TR binlik formatı: "123.456" veya "1.234.567" → son segment 3 haneli
            # Ondalık format   : "123.45" veya "1.5"       → son segment 1-2 haneli
            segments = text_str.split('.')
            last_seg = segments[-1]
            if len(last_seg) == 3 and all(s.isdigit() for s in segments):
                # Binlik ayraç → noktaları sil
                clean_text = text_str.replace('.', '')
            else:
                # Ondalık ayraç → olduğu gibi bırak
                clean_text = text_str
        else:
            # Hiç ayraç yoksa: düz sayı
            clean_text = text_str
            
        return float(clean_text)
    except:
        return 0.0

def format_date_tr(date_str):
    """YYYY-MM-DD stringini DD.MM.YYYY formatına çevirir"""
    if not date_str:
        return ""
    try:
        # Sadece ilk 10 karakteri al (saat vs varsa)
        date_str = str(date_str)[:10]
        parts = date_str.split('-')
        if len(parts) == 3:
            return f"{parts[2]}.{parts[1]}.{parts[0]}"
        return date_str
    except:
        return date_str

def fetch_data():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT rowid, *, SonGuncelleme FROM data")
    rows = cursor.fetchall()
    conn.close()
    return rows

def update_record(rowid, field_name, value):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(f"UPDATE data SET `{field_name}` = ? WHERE rowid = ?", (value, rowid))
    conn.commit()
    conn.close()

def delete_record(rowid):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM data WHERE rowid = ?", (rowid,))
    conn.commit()
    conn.close()

def delete_tender_group(ikn, firma):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM data WHERE "IKN" = ? AND "Yuklenici Firma" = ?', (ikn, firma))
    deleted_count = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted_count

def get_summary_data(show_all=False):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT rowid, *, SonGuncelleme FROM data 
        WHERE (`Odeme Emri Hazirlandi` IS NULL OR `Odeme Emri Hazirlandi` = 0.0)
        ORDER BY CASE WHEN `Parti Son Teslim Tarihi` IS NULL THEN 1 ELSE 0 END, 
                 `Parti Son Teslim Tarihi` ASC, 
                 `Parti No` ASC
    """)
    all_pending = cursor.fetchall()
    
    if show_all:
        conn.close()
        return all_pending
        
    seen_counts = {}
    summary = []
    for record in all_pending:
        ikn = record[1]
        firma = record[2]
        key = (ikn, firma)
        
        current_count = seen_counts.get(key, 0)
        if current_count < 2:
            summary.append(record)
            seen_counts[key] = current_count + 1
    conn.close()
    return summary

def get_aggregated_tender_data():
    rows = fetch_data()
    # Group by (IKN, Firma, Ihale)
    grouped = {}
    for r in rows:
        # r structure: rowid, IKN, Firma, Ihale, Parti No, Tarih, Tutar, ...
        # indexes: 0=rowid, 1=IKN, 2=Firma, 3=Ihale, 4=PartiNo, 5=Tarih, 6=Tutar
        key = (r[1], r[2], r[3])
        if key not in grouped:
            grouped[key] = {
                "total_amount": 0.0,
                "parts": []
            }
        
        tutar = r[6] if r[6] else 0.0
        grouped[key]["total_amount"] += float(tutar)
        grouped[key]["parts"].append(r)
        
    # Convert to list
    result = []
    for key, data in grouped.items():
        result.append({
            "ikn": key[0],
            "firma": key[1],
            "ihale": key[2],
            "total_amount": data["total_amount"],
            "parts": data["parts"]
        })
    return result

def get_firm_summary_data(selected_year=None):
    # Fetch all data raw to have access to dates
    rows = fetch_data()
    # row index 1=IKN, 2=Firma, 3=Ihale, 5=Tarih, 6=Tutar
    firms = {}
    for r in rows:
        f_name = r[2]
        tarih_str = r[5]
        tender_key = (r[1], r[2], r[3]) # IKN, Firma, Ihale
        
        # Filter by year if requested
        if selected_year and selected_year != "Tümü":
            try:
                row_year = tarih_str[:4] # YYYY-MM-DD
                if row_year != selected_year:
                    continue
            except:
                continue

        if f_name not in firms:
            firms[f_name] = {
                "tenders": set(),
                "part_count": 0,
                "total_volume": 0.0
            }
        
        firms[f_name]["tenders"].add(tender_key)
        
        tutar = float(r[6]) if r[6] else 0.0
        firms[f_name]["part_count"] += 1
        firms[f_name]["total_volume"] += tutar
    
    # Convert to list
    result = []
    for name, data in firms.items():
        result.append({
            "name": name,
            "tender_count": len(data["tenders"]),
            "part_count": data["part_count"],
            "volume": data["total_volume"]
        })
    return result

# --- YENİ İHALE EKLEME DİALOGU ---
class NewTenderDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Yeni İhale Kaydı Oluştur")
        self.setFixedWidth(450)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        self.fields = {}
        
        form_items = [
            ("IKN", "Örn: 2026/12345"),
            ("Ihale Adi", "İhale adını giriniz"),
            ("Yuklenici Firma", "Yüklenici Firma bilgisini giriniz"),
            ("Sözleşme Tutarı (TL)", "0.00"),
            ("Parti Sayısı", "1"),
            ("İlk Parti Teslim Tarihi", "YYYY-MM-DD")
        ]

        # Custom handling for specific fields
        
        # IKN
        layout.addWidget(QLabel("<b>IKN:</b>"))
        self.fields["IKN"] = QLineEdit()
        self.fields["IKN"].setPlaceholderText("Örn: 2026/12345")
        layout.addWidget(self.fields["IKN"])

        # Ihale Adi
        layout.addWidget(QLabel("<b>Ihale Adi:</b>"))
        self.fields["Ihale Adi"] = QLineEdit()
        self.fields["Ihale Adi"].setPlaceholderText("İhale adını giriniz")
        layout.addWidget(self.fields["Ihale Adi"])

        # Yuklenici Firma
        layout.addWidget(QLabel("<b>Yuklenici Firma:</b>"))
        self.fields["Yuklenici Firma"] = QLineEdit()
        self.fields["Yuklenici Firma"].setPlaceholderText("Yüklenici Firma bilgisini giriniz")
        layout.addWidget(self.fields["Yuklenici Firma"])

        # Sözleşme Tutarı
        layout.addWidget(QLabel("<b>Sözleşme Tutarı (TL):</b>"))
        self.fields["Sözleşme Tutarı (TL)"] = QLineEdit()
        self.fields["Sözleşme Tutarı (TL)"].setPlaceholderText("Ör. 123.456.789,00")
        # Sadece rakam, nokta ve virgül girişine izin ver
        regex = QRegularExpression("[0-9.,]+")
        validator = QRegularExpressionValidator(regex)
        self.fields["Sözleşme Tutarı (TL)"].setValidator(validator)
        self.fields["Sözleşme Tutarı (TL)"].textChanged.connect(self.format_currency_input)
        layout.addWidget(self.fields["Sözleşme Tutarı (TL)"])

        # Parti Miktarı
        layout.addWidget(QLabel("<b>Malzeme Miktarı (Her parti için kaydedilecek miktar):</b>"))
        self.fields["Parti Miktarı"] = QLineEdit()
        self.fields["Parti Miktarı"].setPlaceholderText("Örn: 5.000")
        # Sadece rakam, nokta ve virgül girişine izin ver
        regex = QRegularExpression("[0-9.,]+")
        validator = QRegularExpressionValidator(regex)
        self.fields["Parti Miktarı"].setValidator(validator)
        self.fields["Parti Miktarı"].textChanged.connect(self.format_currency_input)
        layout.addWidget(self.fields["Parti Miktarı"])

        # Parti Sayısı
        layout.addWidget(QLabel("<b>Toplam Parti Sayısı:</b>"))
        self.fields["Parti Sayısı"] = QLineEdit()
        self.fields["Parti Sayısı"].setText("1")
        # Sadece tam sayı (1-1000 arası)
        self.fields["Parti Sayısı"].setValidator(QIntValidator(1, 1000))
        layout.addWidget(self.fields["Parti Sayısı"])

        # Termin Aralığı (Gün)
        layout.addWidget(QLabel("<b>Termin Aralığı (Gün):</b>"))
        self.fields["Termin Aralığı (Gün)"] = QLineEdit()
        self.fields["Termin Aralığı (Gün)"].setText("30")
        self.fields["Termin Aralığı (Gün)"].setValidator(QIntValidator(1, 365))
        layout.addWidget(self.fields["Termin Aralığı (Gün)"])

        # Sözleşme Tarihi (QDateEdit)
        layout.addWidget(QLabel("<b>Sözleşme Tarihi:</b>"))
        self.date_edit = QDateEdit()
        self.date_edit.setCalendarPopup(True)
        self.date_edit.setDate(QDate.currentDate())
        self.date_edit.setDisplayFormat("dd.MM.yyyy")
        layout.addWidget(self.date_edit)
        self.fields["Sözleşme Tarihi"] = self.date_edit

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Kaydet")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("İptal")
        buttons.accepted.connect(self.process_and_save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def format_currency_input(self, text):
        line_edit = self.sender()
        if not text:
            return
            
        # Mevcut imleç konumu
        cursor = line_edit.cursorPosition()
        # İmleçten önceki rakam/virgül sayısı (noktalar hariç)
        text_before_cursor = text[:cursor]
        digit_count_before = len(text_before_cursor.replace('.', ''))
        
        line_edit.blockSignals(True)
        
        # Noktaları temizle, virgülü koru
        clean_text = text.replace('.', '')
        
        if ',' in clean_text:
            parts = clean_text.split(',', 1)
            integer_part = parts[0]
            decimal_part = parts[1][:2] # Maksimum 2 basamak
            has_comma = True
        else:
            integer_part = clean_text
            decimal_part = ""
            has_comma = False
            
        if integer_part.isdigit():
            # Binlik ayırıcı ekle
            formatted_int = "{:,}".format(int(integer_part)).replace(',', '.')
            new_text = formatted_int
            if has_comma:
                new_text += "," + decimal_part
        else:
            new_text = clean_text
            
        line_edit.setText(new_text)
        
        # İmleç konumunu yeniden hesapla
        new_cursor = 0
        digits_found = 0
        for char in new_text:
            if char.isdigit() or char == ',':
                digits_found += 1
            new_cursor += 1
            if digits_found >= digit_count_before:
                break
        
        line_edit.setCursorPosition(new_cursor)
        line_edit.blockSignals(False)

    def process_and_save(self):
        try:
            ikn = self.fields["IKN"].text()
            ihale = self.fields["Ihale Adi"].text()
            firma = self.fields["Yuklenici Firma"].text()
            
        # Turkish Currency Parsing: Remove dots, replace comma with dot
            tutar_str = self.fields["Sözleşme Tutarı (TL)"].text()
            toplam_tutar = parse_money(tutar_str)
            
            parti_sayisi = int(self.fields["Parti Sayısı"].text())
            parti_miktari = self.fields["Parti Miktarı"].text()
            termin_araligi = int(self.fields["Termin Aralığı (Gün)"].text() or "30")
            
            # Date Handling
            sozlesme_tarihi_qdate = self.fields["Sözleşme Tarihi"].date()
            sozlesme_tarihi = datetime(sozlesme_tarihi_qdate.year(), sozlesme_tarihi_qdate.month(), sozlesme_tarihi_qdate.day())
            sozlesme_tarihi_str = sozlesme_tarihi.strftime("%Y-%m-%d")
            
            # İlk parti teslim tarihi = Sözleşme Tarihi + Termin Aralığı
            ilk_teslim_tarihi = sozlesme_tarihi + timedelta(days=termin_araligi)
            
            parti_tutari = toplam_tutar / parti_sayisi

            timestamp = datetime.now().strftime("%d.%m.%Y %H:%M")
            audit_info = f"Kayıt: {CURRENT_USER} ({timestamp})"

            conn = get_db_connection()
            cursor = conn.cursor()

            for i in range(1, parti_sayisi + 1):
                # Her parti için teslim tarihi (ilk teslimden itibaren termin_araligi ekleyerek)
                teslim_tarihi = (ilk_teslim_tarihi + timedelta(days=termin_araligi*(i-1))).strftime("%Y-%m-%d")
                cursor.execute("""
                    INSERT INTO data 
                    (`IKN`, `Yuklenici Firma`, `Ihale Adi`, `Parti No`, `Parti Son Teslim Tarihi`, `Parti Miktari`, `Parti Tutari`, 
                     `Ambar teslimi gerceklesti`, `Testler basladi`, `Test sonuclari geldi`, `Muayene - Kabul  Evragi imzada`, `Kabul Yapildi`, `Odeme Emri Hazirlandi`, `Aciklama`, `SonGuncelleme`, `Sozlesme Tarihi`)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, 0, '', ?, ?)
                """, (ikn, firma, ihale, i, teslim_tarihi, parti_miktari, parti_tutari, audit_info, sozlesme_tarihi_str))
            
            log_action("Kayıt Oluşturma", f"IKN: {ikn}, Firma: {firma}, Parti Sayısı: {parti_sayisi}")
            conn.commit()
            conn.close()
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Kayıt eklenemedi. Lütfen verileri kontrol edin.\n{e}")

# --- YENİ PARTİ EKLEME DİALOGU ---
class NewBatchDialog(QDialog):
    def __init__(self, ikn, firma, ihale, parent=None):
        super().__init__(parent)
        self.ikn = ikn
        self.firma = firma
        self.ihale = ihale
        self.next_batch_no = self._get_next_batch_no()
        self.last_batch_date = self._get_last_batch_date()
        self.setWindowTitle("Yeni Parti Bilgisi Ekle")
        self.setFixedWidth(500)
        self.setup_ui()

    def _get_next_batch_no(self):
        """Mevcut en yüksek parti no'yu bulup bir artırır."""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT MAX(CAST(`Parti No` AS INTEGER)) FROM data WHERE `IKN` = ? AND `Yuklenici Firma` = ?",
                (self.ikn, self.firma)
            )
            result = cursor.fetchone()[0]
            conn.close()
            return (result or 0) + 1
        except:
            return 1

    def _get_last_batch_date(self):
        """Son partinin teslim tarihini döndürür. Bulunamazsa None."""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                """SELECT `Parti Son Teslim Tarihi` FROM data
                   WHERE `IKN` = ? AND `Yuklenici Firma` = ?
                   ORDER BY CAST(`Parti No` AS INTEGER) DESC LIMIT 1""",
                (self.ikn, self.firma)
            )
            row = cursor.fetchone()
            conn.close()
            if row and row[0]:
                return datetime.strptime(str(row[0])[:10], "%Y-%m-%d")
            return None
        except:
            return None

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        def add_readonly(label_text, value):
            layout.addWidget(QLabel(f"<b>{label_text}:</b>"))
            le = QLineEdit(value)
            le.setReadOnly(True)
            le.setStyleSheet("color: #64748b; background-color: #f1f5f9;")
            layout.addWidget(le)

        add_readonly("IKN", str(self.ikn))
        add_readonly("İşin Adı", str(self.ihale))
        add_readonly("Yüklenici Firma", str(self.firma))
        add_readonly("Yeni Parti No'dan Başlayarak", str(self.next_batch_no))

        # --- Eklenecek Parti Sayısı ---
        layout.addWidget(QLabel("<b>Eklenecek Parti Sayısı:</b>"))
        self.parti_sayisi_edit = QLineEdit()
        self.parti_sayisi_edit.setText("1")
        self.parti_sayisi_edit.setValidator(QIntValidator(1, 1000))
        self.parti_sayisi_edit.setPlaceholderText("Kaç parti eklenecek?")
        self.parti_sayisi_edit.textChanged.connect(self._update_date_preview)
        layout.addWidget(self.parti_sayisi_edit)

        # --- Termin Aralığı ---
        layout.addWidget(QLabel("<b>Termin Aralığı (Gün):</b>"))
        self.termin_edit = QLineEdit()
        self.termin_edit.setValidator(QIntValidator(1, 3650))
        self.termin_edit.setPlaceholderText("Partiler arası gün sayısı")
        self.termin_edit.textChanged.connect(self._on_termin_changed)
        layout.addWidget(self.termin_edit)

        # Son parti tarihi bilgisi etiketi
        if self.last_batch_date:
            son_tarih_str = self.last_batch_date.strftime("%d.%m.%Y")
            info_lbl = QLabel(f"ℹ️ Son parti tarihi: <b>{son_tarih_str}</b>  →  İlk yeni parti tarihi otomatik hesaplanır.")
        else:
            info_lbl = QLabel("ℹ️ Henüz parti kaydı yok. İlk parti tarihini aşağıdan seçin.")
        info_lbl.setStyleSheet("color: #6366f1; font-size: 11px;")
        info_lbl.setWordWrap(True)
        layout.addWidget(info_lbl)

        # --- İlk Yeni Parti Teslim Tarihi ---
        layout.addWidget(QLabel("<b>İlk Yeni Parti Teslim Tarihi:</b>"))
        self.date_edit = QDateEdit()
        self.date_edit.setCalendarPopup(True)
        self.date_edit.setDisplayFormat("dd.MM.yyyy")
        self.date_edit.dateChanged.connect(self._update_date_preview)

        # Sinyal bloke edilerek başlangıç değerleri atanır — preview_lbl henüz oluşturulmadı
        self.termin_edit.blockSignals(True)
        self.date_edit.blockSignals(True)
        if self.last_batch_date:
            # Termin alanı boş başlıyor; kullanıcı girince tarih otomatik hesaplanacak
            self.termin_edit.setText("")
            self.date_edit.setDate(QDate(
                self.last_batch_date.year,
                self.last_batch_date.month,
                self.last_batch_date.day
            ))
        else:
            self.termin_edit.setText("")
            self.date_edit.setDate(QDate.currentDate())
        self.termin_edit.blockSignals(False)
        self.date_edit.blockSignals(False)
        layout.addWidget(self.date_edit)

        # Önizleme etiketi
        self.preview_lbl = QLabel()
        self.preview_lbl.setStyleSheet("color: #0891b2; font-size: 11px; padding: 4px;")
        self.preview_lbl.setWordWrap(True)
        layout.addWidget(self.preview_lbl)
        self._update_date_preview()

        # --- Parti Miktarı ---
        layout.addWidget(QLabel("<b>Parti Miktarı (Her parti için):</b>"))
        self.miktar_edit = QLineEdit()
        self.miktar_edit.setPlaceholderText("Örn: 1.000")
        self.miktar_edit.setValidator(QRegularExpressionValidator(QRegularExpression(r"[0-9\.,]*")))
        self.miktar_edit.textEdited.connect(self._format_numeric)
        layout.addWidget(self.miktar_edit)

        # --- Parti Tutarı ---
        layout.addWidget(QLabel("<b>Parti Tutarı (TL) – Her parti için:</b>"))
        self.amount_edit = QLineEdit()
        self.amount_edit.setPlaceholderText("Ör. 123.456,78")
        regex = QRegularExpression("[0-9.,]+")
        validator = QRegularExpressionValidator(regex)
        self.amount_edit.setValidator(validator)
        self.amount_edit.textEdited.connect(self._format_numeric)
        layout.addWidget(self.amount_edit)

        # --- Açıklama ---
        layout.addWidget(QLabel("<b>Açıklama (isteğe bağlı):</b>"))
        self.desc_edit = QLineEdit()
        self.desc_edit.setPlaceholderText("Açıklama giriniz...")
        layout.addWidget(self.desc_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Kaydet")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("İptal")
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_termin_changed(self):
        """Termin aralığı değişince ilk yeni parti tarihini son parti tarihi + termin olarak günceller."""
        try:
            termin = int(self.termin_edit.text())
        except ValueError:
            # Termin geçersizse tarihe dokunma, sadece önizlemeyi temizle
            self._update_date_preview()
            return

        if self.last_batch_date:
            new_first = self.last_batch_date + timedelta(days=termin)
            self.date_edit.blockSignals(True)
            self.date_edit.setDate(QDate(new_first.year, new_first.month, new_first.day))
            self.date_edit.blockSignals(False)
        self._update_date_preview()

    def _update_date_preview(self):
        """Eklenecek partilerin tarih önizlemesini günceller."""
        try:
            termin = int(self.termin_edit.text() or "30")
        except ValueError:
            termin = 30
        try:
            sayisi = int(self.parti_sayisi_edit.text() or "1")
        except ValueError:
            sayisi = 1

        qd = self.date_edit.date()
        ilk = datetime(qd.year(), qd.month(), qd.day())

        if sayisi <= 0:
            self.preview_lbl.setText("")
            return

        lines = []
        for i in range(min(sayisi, 20)):  # En fazla 20 satır göster
            t = ilk + timedelta(days=termin * i)
            parti_no = self.next_batch_no + i
            lines.append(f"  Parti {parti_no}: {t.strftime('%d.%m.%Y')}")
        if sayisi > 20:
            lines.append(f"  ... ve {sayisi - 20} parti daha")

        self.preview_lbl.setText("📅 Eklenecek partiler:\n" + "\n".join(lines))

    def _format_numeric(self, text):
        """Binlik nokta ayracı ile sayı formatlar."""
        line_edit = self.sender()
        if not text:
            return
        cursor_pos = line_edit.cursorPosition()
        old_len = len(text)
        
        # Sadece sayıları ve virgülü koru
        clean_text = text.replace('.', '')
        if ',' in clean_text:
            parts = clean_text.split(',')
            integer_part = parts[0]
            decimal_part = "," + parts[1][:2]
        else:
            integer_part = clean_text
            decimal_part = ""
            
        if not integer_part and not decimal_part:
            return

        try:
            if integer_part.lstrip('-').isdigit():
                is_negative = integer_part.startswith('-')
                val = integer_part.lstrip('-')
                rev_val = val[::-1]
                groups = [rev_val[i:i+3] for i in range(0, len(rev_val), 3)]
                formatted_int = ".".join(groups)[::-1]
                if is_negative: formatted_int = "-" + formatted_int
                
                new_text = formatted_int + decimal_part
                
                line_edit.blockSignals(True)
                line_edit.setText(new_text)
                line_edit.blockSignals(False)
                
                new_len = len(new_text)
                new_pos = cursor_pos + (new_len - old_len)
                line_edit.setCursorPosition(max(0, new_pos))
        except:
            pass

    def _save(self):
        try:
            termin = int(self.termin_edit.text() or "30")
            sayisi = int(self.parti_sayisi_edit.text() or "1")
            if sayisi < 1:
                QMessageBox.warning(self, "Uyarı", "Eklenecek parti sayısı en az 1 olmalıdır.")
                return

            qd = self.date_edit.date()
            ilk_tarih = datetime(qd.year(), qd.month(), qd.day())
            miktar = self.miktar_edit.text()
            tutar = parse_money(self.amount_edit.text())
            aciklama = self.desc_edit.text()
            timestamp = datetime.now().strftime("%d.%m.%Y %H:%M")
            audit_info = f"Kayıt: {CURRENT_USER} ({timestamp})"

            conn = get_db_connection()
            cursor = conn.cursor()

            for i in range(sayisi):
                parti_no = self.next_batch_no + i
                teslim_tarihi = (ilk_tarih + timedelta(days=termin * i)).strftime("%Y-%m-%d")
                cursor.execute("""
                    INSERT INTO data
                    (`IKN`, `Yuklenici Firma`, `Ihale Adi`, `Parti No`,
                     `Parti Son Teslim Tarihi`, `Parti Miktari`, `Parti Tutari`,
                     `Ambar teslimi gerceklesti`, `Testler basladi`,
                     `Test sonuclari geldi`, `Muayene - Kabul  Evragi imzada`,
                     `Kabul Yapildi`, `Odeme Emri Hazirlandi`, `Aciklama`, `SonGuncelleme`)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, 0, ?, ?)
                """, (self.ikn, self.firma, self.ihale, parti_no,
                      teslim_tarihi, miktar, tutar, aciklama, audit_info))

            conn.commit()
            conn.close()
            log_action("Parti Ekleme",
                       f"IKN: {self.ikn} | Firma: {self.firma} | "
                       f"Parti No: {self.next_batch_no}–{self.next_batch_no + sayisi - 1} | "
                       f"Adet: {sayisi} | Termin: {termin} gün")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Parti eklenemedi:\n{e}")

# --- DÜZENLEME PENCERESİ ---
class EditDialog(QDialog):
    def __init__(self, record, parent=None):
        super().__init__(parent)
        self.record = record
        self.rowid = record[0]
        self.setWindowTitle("Kayıt Düzenle")
        self.setFixedWidth(650)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)

        # --- Temel Bilgiler ---
        layout.addWidget(QLabel("<b>Temel Bilgiler:</b>"))

        self.ihale_edit = QLineEdit(self.record[3])
        layout.addWidget(QLabel("Ihale Adi:"))
        layout.addWidget(self.ihale_edit)

        self.firma_edit = QLineEdit(self.record[2])
        layout.addWidget(QLabel("Yuklenici Firma:"))
        layout.addWidget(self.firma_edit)

        self.parti_no_edit = QLineEdit(str(self.record[4]))
        self.parti_no_edit.setValidator(QIntValidator(1, 1000))
        layout.addWidget(QLabel("Parti No:"))
        layout.addWidget(self.parti_no_edit)

        miktar_val = str(self.record[16]) if len(self.record) > 16 and self.record[16] else ""
        self.miktar_edit = QLineEdit(miktar_val)
        self.miktar_edit.setValidator(QRegularExpressionValidator(QRegularExpression(r"[0-9\.,]*")))
        self.miktar_edit.textEdited.connect(lambda text: self.format_on_type(self.miktar_edit, text))
        layout.addWidget(QLabel("Parti Miktarı:"))
        layout.addWidget(self.miktar_edit)

        # --- Malzeme Detayı (çok satırlı) ---
        from PySide6.QtWidgets import QTextEdit
        layout.addWidget(QLabel("Malzeme Detayı:"))
        self.malzeme_detayi_edit = QTextEdit()
        self.malzeme_detayi_edit.setFixedHeight(80)
        self.malzeme_detayi_edit.setPlaceholderText("Malzeme detayını giriniz...")
        malzeme_val = str(self.record[18]) if len(self.record) > 18 and self.record[18] else ""
        self.malzeme_detayi_edit.setPlainText(malzeme_val)
        layout.addWidget(self.malzeme_detayi_edit)

        self.tutar_edit = QLineEdit(format_money(self.record[6]))
        self.tutar_edit.setValidator(QRegularExpressionValidator(QRegularExpression(r"[0-9\.,]*")))
        self.tutar_edit.textEdited.connect(lambda text: self.format_on_type(self.tutar_edit, text))
        layout.addWidget(QLabel("Parti Tutari:"))
        layout.addWidget(self.tutar_edit)

        self.tarih_edit = QDateEdit()
        self.tarih_edit.setCalendarPopup(True)
        try:
            if self.record[5]:
                d = datetime.strptime(str(self.record[5])[:10], "%Y-%m-%d")
                self.tarih_edit.setDate(QDate(d.year, d.month, d.day))
        except:
            self.tarih_edit.setDate(QDate.currentDate())
        layout.addWidget(QLabel("Teslim Tarihi:"))
        layout.addWidget(self.tarih_edit)
        # NOT: Sözleşme Tarihi bu diyalogda gösterilmez; sadece Toplu Düzenle'de mevcuttur.

        # --- İşlem Adımları ---
        layout.addSpacing(15)
        layout.addWidget(QLabel("<b>İşlem Adımları:</b>"))
        
        # Grid layout for steps (2 columns)
        steps_grid = QGridLayout()
        self.cb_list = {}
        # Indices: 7=Ambar, Heyet=19, 8=Testler, 9=Sonuc, 10=Muayene, 11=Kabul, 13=Odeme
        steps = [("Ambar Teslimi Gerçekleşti", 7), ("Heyet Başkanına Haber Verildi", 19), 
                 ("Testler Başladı", 8), ("Test Sonuçları Geldi", 9),
                 ("Kabul Raporu imzada", 10), ("Kabul Yapıldı", 11), ("Ödeme Belgesi Oluşturuldu", 13)]
        
        for i, (text, idx) in enumerate(steps):
            is_checked = False
            if idx < len(self.record):
                is_checked = (self.record[idx] == 1.0)
            cb = QCheckBox(text)
            cb.setChecked(is_checked)
            self.cb_list[text] = cb
            
            # Fill columns vertically (2 columns total, 4 rows)
            # row: i % 4, column: i // 4
            steps_grid.addWidget(cb, i % 4, i // 4)
            
        layout.addLayout(steps_grid)

        # --- Açıklama ve Son Güncelleme ---
        layout.addSpacing(15)
        
        info_row = QHBoxLayout()
        info_row.addWidget(QLabel("<b>Açıklama:</b>"))
        info_row.addStretch()
        
        # Son Güncelleme Etiketi
        last_upd = str(self.record[15]) if len(self.record) > 15 and self.record[15] else "Bilgi yok"
        self.last_upd_label = QLabel(f"ℹ️ {last_upd}")
        self.last_upd_label.setStyleSheet("color: #6366f1; font-size: 11px; font-weight: bold;")
        info_row.addWidget(self.last_upd_label)
        layout.addLayout(info_row)

        self.aciklama_edit = QLineEdit()
        # idx 14 is Aciklama
        raw_desc = str(self.record[14]) if len(self.record) > 14 and self.record[14] else ""
        # Temizleme: Eski sistemden kalan audit log varsa temizle (isteğe bağlı)
        if " | Düzenleme:" in raw_desc:
            raw_desc = raw_desc.split(" | Düzenleme:")[0]
        elif "Kayıt: " in raw_desc and "(" in raw_desc:
             # Eğer sadece audit log varsa ve açıklama boşsa temizle
             if raw_desc.startswith("Kayıt: "):
                 raw_desc = ""

        self.aciklama_edit.setText(raw_desc)
        layout.addWidget(self.aciklama_edit)
        
        # --- Butonlar ---
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("Değişiklikleri Kaydet")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("İptal")
        
        buttons.accepted.connect(self.save_changes); buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    def format_on_type(self, edit_widget, text):
        if not text: return
        cursor_pos = edit_widget.cursorPosition()
        old_len = len(text)
        clean_text = text.replace('.', '')
        if ',' in clean_text:
            parts = clean_text.split(',')
            integer_part = parts[0]
            decimal_part = "," + parts[1][:2]
        else:
            integer_part = clean_text
            decimal_part = ""
        if not integer_part and not decimal_part: return
        try:
            if integer_part.lstrip('-').isdigit():
                is_negative = integer_part.startswith('-')
                val = integer_part.lstrip('-')
                rev_val = val[::-1]
                groups = [rev_val[i:i+3] for i in range(0, len(rev_val), 3)]
                formatted_int = ".".join(groups)[::-1]
                if is_negative: formatted_int = "-" + formatted_int
                new_text = formatted_int + decimal_part
                edit_widget.blockSignals(True)
                edit_widget.setText(new_text)
                edit_widget.blockSignals(False)
                new_len = len(new_text)
                new_pos = cursor_pos + (new_len - old_len)
                edit_widget.setCursorPosition(max(0, new_pos))
        except: pass

    def save_changes(self):
        try:
            changes = []
            
            # Checkbox güncellemeleri
            for text, cb in self.cb_list.items():
                db_col = COLUMN_MAPPING.get(text, text)
                new_val = 1.0 if cb.isChecked() else 0.0
                
                # Checkbox index bulma (steps listesiyle aynı)
                idx = next((i for t, i in [("Ambar Teslimi Gerçekleşti", 7), ("Heyet Başkanına Haber Verildi", 19),
                                         ("Testler Başladı", 8), ("Test Sonuçları Geldi", 9),
                                         ("Kabul Raporu imzada", 10), ("Kabul Yapıldı", 11), 
                                         ("Ödeme Belgesi Oluşturuldu", 13)] 
                            if t == text), None)
                
                old_val = self.record[idx] if idx is not None and idx < len(self.record) else 0.0
                if new_val != old_val:
                    status_str = "✓" if new_val == 1.0 else "○"
                    changes.append(f"{text}: {status_str}")
                
                update_record(self.rowid, db_col, new_val)

            # Temel bilgiler güncellemeleri
            new_ihale = self.ihale_edit.text()
            if new_ihale != str(self.record[3]):
                changes.append(f"İhale Adı: {new_ihale}")
            update_record(self.rowid, "Ihale Adi", new_ihale)

            new_firma = self.firma_edit.text()
            if new_firma != str(self.record[2]):
                changes.append(f"Firma: {new_firma}")
            update_record(self.rowid, "Yuklenici Firma", new_firma)

            new_parti = int(self.parti_no_edit.text() or "1")
            if new_parti != int(self.record[4]):
                changes.append(f"Parti No: {new_parti}")
            update_record(self.rowid, "Parti No", new_parti)
            
            new_miktar = self.miktar_edit.text()
            old_miktar = str(self.record[16]) if len(self.record) > 16 and self.record[16] else ""
            if new_miktar != old_miktar:
                changes.append(f"Miktar: {new_miktar}")
            update_record(self.rowid, "Parti Miktari", new_miktar)

            # Malzeme Detayı güncelleme
            new_malzeme = self.malzeme_detayi_edit.toPlainText()
            old_malzeme = str(self.record[18]) if len(self.record) > 18 and self.record[18] else ""
            if new_malzeme != old_malzeme:
                changes.append(f"Malzeme Detayı güncellendi")
            update_record(self.rowid, "Malzeme Detayi", new_malzeme)

            new_tutar = parse_money(self.tutar_edit.text())
            if abs(new_tutar - float(self.record[6] or 0)) > 0.01:
                changes.append(f"Tutar: {format_money(new_tutar)} TL")
            update_record(self.rowid, "Parti Tutari", new_tutar)
            
            new_tarih = self.tarih_edit.date().toString("yyyy-MM-dd")
            if new_tarih != str(self.record[5]):
                changes.append(f"Tarih: {format_date_tr(new_tarih)}")
            update_record(self.rowid, "Parti Son Teslim Tarihi", new_tarih)

            # Açıklama ve Audit Log
            new_desc = self.aciklama_edit.text()
            old_desc = str(self.record[14]) if len(self.record) > 14 else ""
            if new_desc != old_desc:
                changes.append(f"Açıklama: {new_desc}")
            
            timestamp = datetime.now().strftime("%d.%m.%Y %H:%M")
            audit_log = f"Düzenleme: {CURRENT_USER} ({timestamp})"
            
            update_record(self.rowid, "Aciklama", new_desc)
            update_record(self.rowid, "SonGuncelleme", audit_log)
            
            # Detailed Logging
            ikn = self.record[1]
            firma = self.record[2]
            
            details_str = f"IKN: {ikn} | Firma: {firma} | Parti: {self.record[4]}"
            if changes:
                details_str += " | Değişiklikler: " + ", ".join(changes)
            else:
                details_str += " | (Değişiklik yapılmadı)"
                
            log_action("Kayıt Güncelleme", details_str)

            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Güncelleme sırasında hata oluştu:\n{e}")

class BulkEditDialog(QDialog):
    def __init__(self, records, parent=None):
        super().__init__(parent)
        self.records = records  # List of full record tuples
        self.setWindowTitle(f"Toplu Kayıt Düzenle ({len(records)} kayıt)")
        self.setFixedWidth(650)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)

        # --- Temel Bilgiler ---
        layout.addWidget(QLabel("<b>Temel Veri Güncellemeleri:</b>"))
        
        form_layout = QGridLayout()
        
        # Seçili kayıtlardan varsayılan değerleri belirle (Eğer hepsi aynıysa göster)
        ikns = set(str(r[1]) for r in self.records if r[1])
        firmas = set(str(r[2]) for r in self.records if r[2])
        ihales = set(str(r[3]) for r in self.records if r[3])
        
        default_ikn = next(iter(ikns)) if len(ikns) == 1 else ""
        default_firma = next(iter(firmas)) if len(firmas) == 1 else ""
        default_ihale = next(iter(ihales)) if len(ihales) == 1 else ""
        
        # Sozlesme Tarihi varsayılan değer (Index 17)
        sozlesmes = set(str(r[17]) for r in self.records if len(r) > 17 and r[17])
        default_sozlesme = next(iter(sozlesmes)) if len(sozlesmes) == 1 else ""

        self.cb_update_ikn = QCheckBox("IKN'yi Güncelle:")
        self.ikn_edit = QLineEdit()
        self.ikn_edit.setText(default_ikn)
        self.ikn_edit.setEnabled(False)
        self.cb_update_ikn.toggled.connect(self.ikn_edit.setEnabled)
        form_layout.addWidget(self.cb_update_ikn, 0, 0)
        form_layout.addWidget(self.ikn_edit, 0, 1)

        self.cb_update_firma = QCheckBox("Yüklenici Firmayı Güncelle:")
        self.firma_edit = QLineEdit()
        self.firma_edit.setText(default_firma)
        self.firma_edit.setEnabled(False)
        self.cb_update_firma.toggled.connect(self.firma_edit.setEnabled)
        form_layout.addWidget(self.cb_update_firma, 1, 0)
        form_layout.addWidget(self.firma_edit, 1, 1)

        self.cb_update_ihale = QCheckBox("İhale Adını Güncelle:")
        self.ihale_edit = QLineEdit()
        self.ihale_edit.setText(default_ihale)
        self.ihale_edit.setEnabled(False)
        self.cb_update_ihale.toggled.connect(self.ihale_edit.setEnabled)
        form_layout.addWidget(self.cb_update_ihale, 2, 0)
        form_layout.addWidget(self.ihale_edit, 2, 1)

        self.cb_update_sozlesme = QCheckBox("Sözleşme Tarihini Güncelle:")
        self.sozlesme_edit = QDateEdit()
        self.sozlesme_edit.setCalendarPopup(True)
        if default_sozlesme:
            try:
                d = datetime.strptime(default_sozlesme[:10], "%Y-%m-%d")
                self.sozlesme_edit.setDate(QDate(d.year, d.month, d.day))
            except:
                self.sozlesme_edit.setDate(QDate.currentDate())
        else:
            self.sozlesme_edit.setDate(QDate.currentDate())
        self.sozlesme_edit.setEnabled(False)
        self.cb_update_sozlesme.toggled.connect(self.sozlesme_edit.setEnabled)
        form_layout.addWidget(self.cb_update_sozlesme, 3, 0)
        form_layout.addWidget(self.sozlesme_edit, 3, 1)
        
        self.cb_update_miktar = QCheckBox("Miktarı Güncelle:")
        self.miktar_edit = QLineEdit()
        self.miktar_edit.setEnabled(False)
        self.miktar_edit.setValidator(QRegularExpressionValidator(QRegularExpression(r"[0-9\.,]*")))
        self.miktar_edit.textEdited.connect(lambda text: self.format_on_type(self.miktar_edit, text))
        self.cb_update_miktar.toggled.connect(self.miktar_edit.setEnabled)
        form_layout.addWidget(self.cb_update_miktar, 4, 0)
        form_layout.addWidget(self.miktar_edit, 4, 1)
        
        self.cb_update_tutar = QCheckBox("Tutarı Güncelle:")
        self.tutar_edit = QLineEdit()
        self.tutar_edit.setEnabled(False)
        self.tutar_edit.setValidator(QRegularExpressionValidator(QRegularExpression(r"[0-9\.,]*")))
        self.tutar_edit.textEdited.connect(lambda text: self.format_on_type(self.tutar_edit, text))
        self.cb_update_tutar.toggled.connect(self.tutar_edit.setEnabled)
        form_layout.addWidget(self.cb_update_tutar, 5, 0)
        form_layout.addWidget(self.tutar_edit, 5, 1)

        self.cb_update_aciklama = QCheckBox("Açıklamayı Güncelle:")
        self.aciklama_edit = QLineEdit()
        self.aciklama_edit.setEnabled(False)
        self.cb_update_aciklama.toggled.connect(self.aciklama_edit.setEnabled)
        form_layout.addWidget(self.cb_update_aciklama, 6, 0)
        form_layout.addWidget(self.aciklama_edit, 6, 1)
        
        layout.addLayout(form_layout)

        # --- İşlem Adımları ---
        layout.addSpacing(15)
        layout.addWidget(QLabel("<b>İşlem Adımları (Durum Güncellemeleri):</b>"))
        layout.addWidget(QLabel("<small><i>( Açık Gri Kare : Mevcut Durumu Değiştirme _____ ✓ : Onayla _____ Boş Kare : Onayı İptal Et / Onaylama )</i></small>"))
        
        steps_grid = QGridLayout()
        self.status_checks = {}
        
        steps = [("Ambar Teslimi Gerçekleşti", 7), ("Heyet Başkanına Haber Verildi", 19), 
                 ("Testler Başladı", 8), ("Test Sonuçları Geldi", 9),
                 ("Kabul Raporu imzada", 10), ("Kabul Yapıldı", 11), ("Ödeme Belgesi Oluşturuldu", 13)]
        
        for i, (text, idx) in enumerate(steps):
            cb = QCheckBox(text)
            cb.setTristate(True)
            cb.setCheckState(Qt.CheckState.PartiallyChecked) # Başlangıçta "Değiştirme" (Kare/Belirsiz)
            self.status_checks[text] = cb
            steps_grid.addWidget(cb, i % 4, i // 4)
            
        layout.addLayout(steps_grid)
        
        layout.addSpacing(15)
        
        # --- Butonlar ---
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("Toplu Değişiklikleri Kaydet")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("İptal")
        
        buttons.accepted.connect(self.save_changes); buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def format_on_type(self, edit_widget, text):
        """Sayı yazılırken binlik ayraç ekleyen ve numerik formatı koruyan fonksiyon."""
        if not text:
            return
            
        cursor_pos = edit_widget.cursorPosition()
        old_len = len(text)
        
        # Sadece sayıları ve virgülü koru
        clean_text = text.replace('.', '')
        if ',' in clean_text:
            parts = clean_text.split(',')
            integer_part = parts[0]
            decimal_part = "," + parts[1][:2] # Max 2 ondalık
        else:
            integer_part = clean_text
            decimal_part = ""
            
        if not integer_part and not decimal_part:
            return

        try:
            # Binlik ayraçları ekle
            if integer_part.lstrip('-').isdigit():
                is_negative = integer_part.startswith('-')
                val = integer_part.lstrip('-')
                
                # Sondan başlayarak her 3 hane arasına nokta koy
                rev_val = val[::-1]
                groups = [rev_val[i:i+3] for i in range(0, len(rev_val), 3)]
                formatted_int = ".".join(groups)[::-1]
                if is_negative: formatted_int = "-" + formatted_int
                
                new_text = formatted_int + decimal_part
                
                edit_widget.blockSignals(True)
                edit_widget.setText(new_text)
                edit_widget.blockSignals(False)
                
                # Kursör pozisyonunu ayarla
                new_len = len(new_text)
                new_pos = cursor_pos + (new_len - old_len)
                edit_widget.setCursorPosition(max(0, new_pos))
        except:
            pass

    def save_changes(self):
        reply = QMessageBox.question(self, "Toplu İşlem Onayı", f"Seçili {len(self.records)} kaydı güncellemek istediğinize emin misiniz?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            changes_summary = []
            
            do_ikn = self.cb_update_ikn.isChecked()
            new_ikn = self.ikn_edit.text() if do_ikn else None
            if do_ikn: changes_summary.append("IKN")

            do_firma = self.cb_update_firma.isChecked()
            new_firma = self.firma_edit.text() if do_firma else None
            if do_firma: changes_summary.append("Firma")

            do_ihale = self.cb_update_ihale.isChecked()
            new_ihale = self.ihale_edit.text() if do_ihale else None
            if do_ihale: changes_summary.append("İhale Adı")
            
            do_sozlesme = self.cb_update_sozlesme.isChecked()
            new_sozlesme_qdate = self.sozlesme_edit.date()
            new_sozlesme_dt = datetime(new_sozlesme_qdate.year(), new_sozlesme_qdate.month(), new_sozlesme_qdate.day())
            new_sozlesme_str = new_sozlesme_dt.strftime("%Y-%m-%d")
            if do_sozlesme: changes_summary.append("Sözleşme Tarihi & Bağlı Teslim Tarihleri")
            
            do_miktar = self.cb_update_miktar.isChecked()
            new_miktar = self.miktar_edit.text() if do_miktar else None
            if do_miktar: changes_summary.append("Miktar")
            
            do_tutar = self.cb_update_tutar.isChecked()
            new_tutar = parse_money(self.tutar_edit.text()) if do_tutar else None
            if do_tutar: changes_summary.append("Tutar")
            
            do_aciklama = self.cb_update_aciklama.isChecked()
            new_aciklama = self.aciklama_edit.text() if do_aciklama else None
            if do_aciklama: changes_summary.append("Açıklama")
            
            status_updates = {}
            for text, cb in self.status_checks.items():
                state = cb.checkState()
                if state == Qt.CheckState.Checked:
                    status_updates[text] = 1.0
                    changes_summary.append(f"{text} (✓)")
                elif state == Qt.CheckState.Unchecked:
                    status_updates[text] = 0.0
                    changes_summary.append(f"{text} (○)")
                    
            if not changes_summary:
                QMessageBox.warning(self, "Uyarı", "Hiçbir değişiklik seçilmedi.")
                return

            updated_details = []
            timestamp = datetime.now().strftime("%d.%m.%Y %H:%M")
            audit_log = f"Toplu Düzenleme: {CURRENT_USER} ({timestamp})"

            for r in self.records:
                rowid = r[0]
                
                if do_ikn: update_record(rowid, "IKN", new_ikn)
                if do_firma: update_record(rowid, "Yuklenici Firma", new_firma)
                if do_ihale: update_record(rowid, "Ihale Adi", new_ihale)
                
                if do_sozlesme:
                    old_sozlesme_str = str(r[17]) if len(r) > 17 and r[17] else ""
                    if old_sozlesme_str:
                        try:
                            old_sozlesme_dt = datetime.strptime(old_sozlesme_str[:10], "%Y-%m-%d")
                            delta = (new_sozlesme_dt - old_sozlesme_dt).days
                            if delta != 0:
                                old_teslim_str = str(r[5])[:10] if r[5] else ""
                                if old_teslim_str:
                                    old_teslim_dt = datetime.strptime(old_teslim_str, "%Y-%m-%d")
                                    new_teslim_dt = old_teslim_dt + timedelta(days=delta)
                                    new_teslim_str = new_teslim_dt.strftime("%Y-%m-%d")
                                    update_record(rowid, "Parti Son Teslim Tarihi", new_teslim_str)
                        except: pass
                    update_record(rowid, "Sozlesme Tarihi", new_sozlesme_str)

                if do_miktar: update_record(rowid, "Parti Miktari", new_miktar)
                if do_tutar: update_record(rowid, "Parti Tutari", new_tutar)
                if do_aciklama: update_record(rowid, "Aciklama", new_aciklama)
                
                for state_text, state_val in status_updates.items():
                    db_col = COLUMN_MAPPING.get(state_text, state_text)
                    update_record(rowid, db_col, state_val)
                
                update_record(rowid, "SonGuncelleme", audit_log)
                
                ihale_adi = str(r[3])
                parti_no = str(r[4])
                updated_details.append(f"{ihale_adi} (Parti: {parti_no})")
                
            log_desc = f"Alanlar ({', '.join(changes_summary)}) | Toplam {len(self.records)} Kayıt: " + ", ".join(updated_details)
            log_action("Toplu Gelişmiş Düzenleme", log_desc)
            
            QMessageBox.information(self, "Başarılı", f"Seçili {len(self.records)} kayıt başarıyla güncellendi.")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Toplu güncelleme sırasında hata oluştu:\n{e}")

# --- ÖZET SAYFASI ---
# (SummaryWidget aynı, değişmedi)

# --- DETAY
# --- ÖZET SAYFASI ---
class SummaryWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.all_summary_data = []
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Üst Başlık ve Filtre Paneli
        header_layout = QHBoxLayout()
        title = QLabel("Yakın Tarihli Parti Bilgileri")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #5e35b1; padding: 5px;")
        header_layout.addWidget(title)
        header_layout.addStretch()
        
        # Filtre Elemanları
        self.cb_firm = QComboBox()
        self.cb_firm.setView(QListView())
        self.cb_firm.setItemDelegate(DropdownDelegate())
        self.cb_firm.setMinimumWidth(150)
        self.cb_firm.addItem("Tümü")
        self.cb_firm.currentTextChanged.connect(self.firm_changed)
        
        self.cb_tender = QComboBox()
        self.cb_tender.setView(QListView())
        self.cb_tender.setItemDelegate(DropdownDelegate())
        self.cb_tender.setMinimumWidth(150)
        self.cb_tender.addItem("Tümü")
        self.cb_tender.currentTextChanged.connect(self.apply_filters)
        
        self.cb_sort = QComboBox()
        self.cb_sort.setView(QListView())
        self.cb_sort.setItemDelegate(DropdownDelegate())
        self.cb_sort.setMinimumWidth(150)
        self.cb_sort.addItems(["Tarihe Göre", "Yüklenici Adına Göre", "İhale Adına Göre"])
        self.cb_sort.currentTextChanged.connect(self.apply_filters)

        btn_clr = QPushButton("Temizle")
        btn_clr.clicked.connect(self.clear_filters)

        self.btn_show_all = QPushButton("Tümünü Göster")
        self.btn_show_all.setCheckable(True)
        self.btn_show_all.setObjectName("SecondaryBtn") # Başlangıçta gri (pasif)
        self.btn_show_all.setEnabled(False)
        self.btn_show_all.clicked.connect(self.refresh_summary)
        
        header_layout.addWidget(QLabel("Sıralama:"))
        header_layout.addWidget(self.cb_sort)
        header_layout.addWidget(QLabel("Firma:"))
        header_layout.addWidget(self.cb_firm)
        header_layout.addWidget(QLabel("İhale:"))
        header_layout.addWidget(self.cb_tender)
        header_layout.addWidget(btn_clr)
        header_layout.addWidget(self.btn_show_all)
        
        layout.addLayout(header_layout)

        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        container = QWidget(); self.cards_layout = QVBoxLayout(container)
        self.cards_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        scroll.setWidget(container); layout.addWidget(scroll)
        
        self.refresh_summary()
        
    def refresh_summary(self):
        show_all = self.btn_show_all.isChecked()
        self.all_summary_data = get_summary_data(show_all=show_all)
        self.update_firm_dropdown()

    def update_firm_dropdown(self):
        current_firm = self.cb_firm.currentText()
        self.cb_firm.blockSignals(True)
        self.cb_firm.clear()
        self.cb_firm.addItem("Tümü")
        
        firms = sorted(list(set(str(r[2]) for r in self.all_summary_data)), key=tr_key)
        self.cb_firm.addItems(firms)
        
        if current_firm in firms:
            self.cb_firm.setCurrentText(current_firm)
        else:
            self.cb_firm.setCurrentIndex(0)
            
        self.cb_firm.blockSignals(False)
        self.firm_changed()

    def firm_changed(self):
        current_tender = self.cb_tender.currentText()
        self.cb_tender.blockSignals(True)
        self.cb_tender.clear()
        self.cb_tender.addItem("Tümü")
        
        firm = self.cb_firm.currentText()
        tenders = sorted(list(set(str(r[3]) for r in self.all_summary_data if firm == "Tümü" or str(r[2]) == firm)), key=tr_key)
        self.cb_tender.addItems(tenders)
        
        if current_tender in tenders:
            self.cb_tender.setCurrentText(current_tender)
        else:
            self.cb_tender.setCurrentIndex(0)
            
        self.cb_tender.blockSignals(False)
        self.apply_filters()

    def apply_filters(self):
        # Yüklenici ya da iş seçilirse "Tümünü Göster" butonunu aktif et ve mavi yap
        is_filtered = (self.cb_firm.currentIndex() > 0 or self.cb_tender.currentIndex() > 0)
        self.btn_show_all.setEnabled(is_filtered)
        
        # Stil güncelleme: Aktifse mavi (default), pasifse gri (SecondaryBtn)
        self.btn_show_all.setObjectName("" if is_filtered else "SecondaryBtn")
        self.btn_show_all.style().unpolish(self.btn_show_all)
        self.btn_show_all.style().polish(self.btn_show_all)

        if not is_filtered and self.btn_show_all.isChecked():
            self.btn_show_all.setChecked(False)
            self.refresh_summary()
            return

        # Ekrandaki kartları temizle
        while self.cards_layout.count():
            item = self.cards_layout.takeAt(0)
            if item.widget(): item.widget().deleteLater()
            
        f = self.cb_firm.currentText()
        t = self.cb_tender.currentText()
        s = self.cb_sort.currentText()
        
        filtered = [r for r in self.all_summary_data if 
                    (f == "Tümü" or str(r[2]) == f) and 
                    (t == "Tümü" or str(r[3]) == t)]
                    
        # Sorting Logic
        if s == "Tarihe Göre":
            # Index 5 is 'Parti Son Teslim Tarihi'
            filtered.sort(key=lambda x: str(x[5]) if x[5] else "9999-99-99")
        elif s == "Yüklenici Adına Göre":
            # Index 2 Is 'Yuklenici Firma'
            filtered.sort(key=lambda x: str(x[2]).lower())
        elif s == "İhale Adına Göre":
            # Index 3 is 'Ihale Adi'
            filtered.sort(key=lambda x: str(x[3]).lower())
        
        if not filtered:
            empty_lbl = QLabel("Kriterlere uygun bekleyen teslimat bulunmuyor. 🔍" if self.all_summary_data else "Bekleyen teslimat bulunmuyor. 🎉")
            empty_lbl.setAlignment(Qt.AlignCenter)
            empty_lbl.setStyleSheet("font-size: 16px; color: #64748b; margin-top: 50px;")
            self.cards_layout.addWidget(empty_lbl)
            return

        for record in filtered:
            self.cards_layout.addWidget(self.create_card(record))

    def clear_filters(self):
        self.cb_firm.setCurrentIndex(0)
        self.cb_tender.setCurrentIndex(0)
        self.cb_sort.setCurrentIndex(0)
        self.apply_filters()
            
    def create_card(self, record):
        is_completed = (len(record) > 11 and record[11] == 1.0)
        date_color = get_date_color(record[5], is_completed)
        is_dark = self.parent_window.is_dark_mode if self.parent_window else False
        
        bg_color = "#475569" if is_dark else "white"
        border_color = date_color if date_color else ("#64748b" if is_dark else "#e2e8f0")
        text_color = "#f8fafc" if is_dark else "#1e293b"
        sub_text_color = "#94a3b8" if is_dark else "#64748b"
        
        card = QFrame()
        card.setObjectName("Card")
        card.setStyleSheet(f"""
            #Card {{
                background-color: {bg_color}; 
                border: 2px solid {border_color}; 
                border-radius: 12px; 
                margin: 5px 10px;
            }}
            #Card:hover {{
                border: 2px solid #6366f1;
            }}
        """)
        
        # Shadow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setXOffset(0)
        shadow.setYOffset(4)
        shadow.setColor(QColor(0, 0, 0, 40 if is_dark else 20))
        card.setGraphicsEffect(shadow)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        h_head = QHBoxLayout()
        ikn_lbl = QLabel(f" IKN: {record[1]} ")
        ikn_bg_color = "#1e293b" if is_dark else "#f1f5f9"
        ikn_style = f"background-color: {ikn_bg_color}; border-radius: 4px; padding: 2px;"
        ikn_lbl.setStyleSheet(f"font-weight: bold; color: {('#818cf8' if is_dark else '#6366f1')}; font-size: 16px; {ikn_style}")
        h_head.addWidget(ikn_lbl)
        
        if date_color:
            status_tag = QLabel("⚠️ KABUL İŞLEMİ TAMAMLANMADI" if date_color == "#ef4444" else "⏳ TESLİM SÜRESİ YAKLAŞIYOR")
            status_tag.setStyleSheet(f"color: white; background-color: {date_color}; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;")
            h_head.addWidget(status_tag)
            
        h_head.addStretch()
        
        btn = QPushButton("✏️ Düzenle")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        # Indigo colors consistent with 'Temizle' button
        btn.setStyleSheet("""
            QPushButton { 
                padding: 4px 12px; 
                font-size: 12px; 
                background-color: #6366f1; 
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover { 
                background-color: #4f46e5; 
            }
        """)
        btn.clicked.connect(lambda: self.open_edit(record))
        h_head.addWidget(btn)
        
        layout.addLayout(h_head)

        title_lbl = QLabel(str(record[3]))
        title_lbl.setWordWrap(True)
        title_bg_color = "#1e293b" if is_dark else "#f8fafc"
        title_style = f"background-color: {title_bg_color}; border-radius: 6px; padding: 5px;"
        title_lbl.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {text_color}; {title_style}")
        layout.addWidget(title_lbl)
        
        # Info Row
        info_layout = QHBoxLayout()
        firma_lbl = QLabel(f"🏢 {record[2]}")
        miktar_val = str(record[16]) if len(record) > 16 and record[16] else "-"
        miktar_lbl = QLabel(f"🔢 Miktar: {miktar_val}")
        tutar_lbl = QLabel(f"💰 {format_money(record[6])} TL")
        parti_lbl = QLabel(f"📦 Parti: {record[4]}")
        tarih_val = format_date_tr(record[5]) if record[5] else "-"
        tarih_lbl = QLabel(f"📅 {tarih_val}")
        
        for lbl in [firma_lbl, miktar_lbl, tutar_lbl, parti_lbl, tarih_lbl]:
            lbl_bg_color = "#1e293b" if is_dark else "#f1f5f9"
            lbl_style = f"background-color: {lbl_bg_color}; border-radius: 4px; padding: 3px 8px;"
            lbl.setStyleSheet(f"color: {sub_text_color}; font-size: 14px; {lbl_style}")
            info_layout.addWidget(lbl)
            if lbl != tarih_lbl:
                info_layout.addSpacing(10)
        
        info_layout.addStretch()
        layout.addLayout(info_layout)
        
        # Status Box
        status_box = QFrame()
        status_box.setStyleSheet(f"background-color: {('#1e293b' if is_dark else 'white')}; border-radius: 8px; padding: 10px;")
        status_layout = QVBoxLayout(status_box)
        
        # Horizontal layout for labels to fit side-by-side
        row_steps = QHBoxLayout()
        row_steps.setSpacing(15)
        
        steps = [("Ambar Teslimi Gerçekleşti", 7), ("Heyet Başkanına Haber Verildi", 19), 
                 ("Testler Başladı", 8), ("Test Sonuçları Geldi", 9),
                 ("Kabul Raporu imzada", 10), ("Kabul Yapıldı", 11), ("Ödeme Belgesi Oluşturuldu", 13)]
        
        for text, idx in steps:
            is_checked = (idx < len(record) and record[idx] == 1.0)
            dot = "●"
            lbl = QLabel(f"{dot} {text}")
            if is_checked:
                color = "#4ade80" if is_dark else "#16a34a"  # Canlı Yeşil (Karanlıkta açık, Aydınlıkta koyu)
            else:
                # Aydınlık modda daha koyu gri (#64748b), karanlık modda orta gri (#94a3b8)
                color = "#94a3b8" if is_dark else "#64748b" 
            lbl.setStyleSheet(f"font-size: 12px; font-weight: bold; color: {color};")
            row_steps.addWidget(lbl)
        
        row_steps.addStretch()
        status_layout.addLayout(row_steps)
        
        desc = record[14] if len(record) > 14 and record[14] else ""
        if desc:
            d_lbl = QLabel(f"📝 {desc}")
            # Dynamic styling for better readability in dark mode
            d_color = "#94a3b8" if is_dark else "#475569"
            d_border = "#334155" if is_dark else "#e2e8f0"
            d_lbl.setStyleSheet(f"color: {d_color}; font-size: 14px; border-top: 1px solid {d_border}; margin-top: 5px; padding-top: 5px;")
            status_layout.addWidget(d_lbl)
            
        # Son Güncelleme (Audit Info) displayed at the bottom of the card
        last_upd_val = str(record[15]) if len(record) > 15 and record[15] else ""
        if last_upd_val:
            upd_lbl = QLabel(f"ℹ️ {last_upd_val}")
            upd_color = "#94a3b8" if is_dark else "#64748b"
            upd_lbl.setStyleSheet(f"color: {upd_color}; font-size: 11px; margin-top: 2px;")
            upd_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
            layout.addWidget(upd_lbl)

        layout.addWidget(status_box)
        return card

    def open_edit(self, record):
        if EditDialog(record, self).exec():
            self.refresh_summary()
            if self.parent_window: self.parent_window.refresh_all()

# --- İHALE DETAYLARI SEKME ---
class TenderWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.current_status_filter = "all" # all, active, completed
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # --- FILTER BUTTONS ---
        btn_layout = QHBoxLayout()
        self.btn_all = QPushButton("Tüm İşler")
        self.btn_active = QPushButton("Devam Edenler")
        self.btn_completed = QPushButton("Tamamlananlar")
        
        for btn in [self.btn_all, self.btn_active, self.btn_completed]:
            btn.setCheckable(True)
            btn.setStyleSheet("""
                QPushButton { background-color: #cbd5e1; color: #1e293b; border: 1px solid #94a3b8; padding: 6px; border-radius: 6px; }
                QPushButton:hover { background-color: #94a3b8; }
                QPushButton:checked { background-color: #6366f1; color: white; border: 1px solid #6366f1; }
                QPushButton:checked:hover { background-color: #4f46e5; }
            """)
            btn_layout.addWidget(btn)
        
        btn_layout.addStretch()
        
        self.total_label = QLabel("<b>GENEL TOPLAM: 0,00 TL</b>")
        is_dark = self.parent_window.is_dark_mode if self.parent_window else False
        lbl_bg = "#1e293b" if is_dark else "#f1f5f9"
        self.total_label.setStyleSheet(f"font-size: 14px; color: #6366f1; background-color: {lbl_bg}; padding: 5px 12px; border-radius: 6px; border: 1px solid #6366f1;")
        btn_layout.addWidget(self.total_label)
        
        btn_layout.addSpacing(10)
        
        self.remaining_total_label = QLabel("<b>KALAN TOPLAM: 0,00 TL</b>")
        self.remaining_total_label.setStyleSheet(f"font-size: 14px; color: #ef4444; background-color: {lbl_bg}; padding: 5px 12px; border-radius: 6px; border: 1px solid #ef4444;")
        btn_layout.addWidget(self.remaining_total_label)

        layout.addLayout(btn_layout)
        
        self.btn_all.setChecked(True)
        self.btn_all.clicked.connect(lambda: self.set_status_filter("all"))
        self.btn_active.clicked.connect(lambda: self.set_status_filter("active"))
        self.btn_completed.clicked.connect(lambda: self.set_status_filter("completed"))

        layout.addSpacing(10)

        # Splitter creates a resizable divider between two tables
        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter)
        
        # --- TOP PANEL: TENDER LIST ---
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 10)
        
        title_lbl = QLabel("📁 İhale Listesi (Detayları görmek için bir satır seçin)")
        title_lbl.setStyleSheet("font-size: 14px; font-weight: bold; color: #5e35b1;")
        top_layout.addWidget(title_lbl)
        
        self.tender_table = QTableWidget()
        self.tender_table.setAlternatingRowColors(True)
        self.tender_table.setColumnCount(6)
        self.tender_table.setHorizontalHeaderLabels(["IKN", "Firma", "İhale Adı", "Toplam Tutar", "Toplam Parti", "Kalan Parti"])
        self.tender_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tender_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.tender_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tender_table.itemSelectionChanged.connect(self.on_tender_selected)
        
        header = self.tender_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch) # Stretch 'Ihale Adi'
        
        top_layout.addWidget(self.tender_table)
        splitter.addWidget(top_widget)
        
        # --- BOTTOM PANEL: PART DETAILS ---
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 10, 0, 0)
        
        detail_lbl = QLabel("📦 Seçili İhalenin Partileri")
        detail_lbl.setStyleSheet("font-size: 14px; font-weight: bold; color: #5e35b1;")
        
        h_detail = QHBoxLayout()
        h_detail.addWidget(detail_lbl)
        h_detail.addStretch()
        self.detail_total_label = QLabel("<b>Seçili İhalede Bekleyen Alacak: 0,00 TL</b>")
        is_dark = self.parent_window.is_dark_mode if self.parent_window else False
        lbl_bg = "#1e293b" if is_dark else "#f1f5f9"
        self.detail_total_label.setStyleSheet(f"font-size: 13px; color: #ef4444; background-color: {lbl_bg}; padding: 4px 10px; border-radius: 4px; border: 1px solid #ef4444;")
        h_detail.addWidget(self.detail_total_label)
        bottom_layout.addLayout(h_detail)
        
        self.part_table = QTableWidget()
        self.part_table.setAlternatingRowColors(True)
        self.part_table.setColumnCount(6)
        self.part_table.setHorizontalHeaderLabels(["Parti No", "Teslim Tarihi", "Miktar", "Tutar", "Durum", "Açıklama"])
        self.part_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        
        header_part = self.part_table.horizontalHeader()
        header_part.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header_part.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch) # Stretch 'Aciklama'
        
        bottom_layout.addWidget(self.part_table)
        splitter.addWidget(bottom_widget)
        
        # Initial sizing
        splitter.setSizes([300, 300])

        self.refresh_data()

    def set_status_filter(self, mode):
        self.current_status_filter = mode
        self.btn_all.setChecked(mode == "all")
        self.btn_active.setChecked(mode == "active")
        self.btn_completed.setChecked(mode == "completed")
        self.refresh_data()

    def refresh_data(self):
        self.tender_table.blockSignals(True)
        # Get all data
        all_data = get_aggregated_tender_data()
        
        # Calculate Stats
        count_all = 0
        count_active = 0
        count_completed = 0
        
        # Apply Filter
        filtered_data = []
        for item in all_data:
            # Check completion status of the TENDER (all parts must be completed)
            is_tender_completed = True
            for part in item["parts"]:
                # part[13] is 'Odeme Emri Hazirlandi'
                if not (len(part) > 13 and part[13] == 1.0):
                    is_tender_completed = False
                    break
            
            # Update Stats
            count_all += 1
            if is_tender_completed:
                count_completed += 1
            else:
                count_active += 1
            
            # Filter Logic
            if self.current_status_filter == "all":
                filtered_data.append(item)
            elif self.current_status_filter == "active" and not is_tender_completed:
                filtered_data.append(item)
            elif self.current_status_filter == "completed" and is_tender_completed:
                filtered_data.append(item)

        # Update Button Texts
        self.btn_all.setText(f"Tüm İşler ({count_all})")
        self.btn_active.setText(f"Devam Edenler ({count_active})")
        self.btn_completed.setText(f"Tamamlananlar ({count_completed})")

        # Update Grand Total
        grand_total = sum(item["total_amount"] for item in filtered_data)
        self.total_label.setText(f"<b>GENEL TOPLAM: {format_money(grand_total)} TL</b>")

        # Update Remaining Total (Unpaid parts where index 13 is not 1.0)
        remaining_total = 0.0
        for item in filtered_data:
            for part in item["parts"]:
                # part[13] is 'Odeme Emri Hazirlandi'
                if not (len(part) > 13 and part[13] == 1.0):
                    remaining_total += float(part[6] or 0.0)
        self.remaining_total_label.setText(f"<b>KALAN TOPLAM: {format_money(remaining_total)} TL</b>")

        self.tender_table.setRowCount(len(filtered_data))
        self.tender_table.setSortingEnabled(False)
        
        for i, item in enumerate(filtered_data):
            # Column 0: IKN (Store full data in UserRole + 1)
            ikn_item = QTableWidgetItem(str(item["ikn"]))
            ikn_item.setData(Qt.ItemDataRole.UserRole + 1, item) 
            self.tender_table.setItem(i, 0, ikn_item)
            
            # Column 1: Firma
            self.tender_table.setItem(i, 1, QTableWidgetItem(str(item["firma"])))
            
            # Column 2: Ihale Adi - Sortable
            self.tender_table.setItem(i, 2, QTableWidgetItem(str(item["ihale"])))
            
            # Column 3: Toplam Tutar - Sortable Numeric
            tutar_item = SortableTableWidgetItem(format_money(item["total_amount"]) + " TL")
            tutar_item.setData(Qt.ItemDataRole.UserRole, item["total_amount"])
            tutar_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.tender_table.setItem(i, 3, tutar_item)
            
            # Column 4: Toplam Parti Sayisi - Sortable Numeric
            part_count = len(item["parts"])
            p_item = SortableTableWidgetItem(str(part_count))
            p_item.setData(Qt.ItemDataRole.UserRole, part_count)
            p_item.setTextAlignment(Qt.AlignCenter)
            self.tender_table.setItem(i, 4, p_item)

            # Column 5: Kalan Parti Sayisi - Sortable Numeric
            t_completed = 0
            for p in item["parts"]:
                # part[13] is 'Odeme Emri Hazirlandi'
                if len(p) > 13 and p[13] == 1.0:
                    t_completed += 1
            remaining = part_count - t_completed
            
            rem_item = SortableTableWidgetItem(str(remaining))
            rem_item.setData(Qt.ItemDataRole.UserRole, remaining)
            rem_item.setTextAlignment(Qt.AlignCenter)
            
            # Highlight if remaining > 0 (optional visual cue)
            if remaining > 0:
                rem_item.setForeground(QColor("#ef4444")) # Red text for pending
                rem_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            else:
                 is_dark = self.parent_window.is_dark_mode if self.parent_window else False
                 rem_item.setForeground(QColor("#4ade80" if is_dark else "#16a34a")) # Green for all done

            self.tender_table.setItem(i, 5, rem_item)
            
        self.tender_table.setSortingEnabled(True)
        self.tender_table.blockSignals(False)
        
        # Clear detail view if selection lost/reset or if the selected item is filtered out
        if not self.tender_table.selectedItems():
            self.part_table.setRowCount(0)
            self.detail_total_label.setText("<b>Seçili İhalede Bekleyen Alacak: 0,00 TL</b>")

    def on_tender_selected(self):
        row = self.tender_table.currentRow()
        if row < 0: 
            return
        
        item = self.tender_table.item(row, 0)
        data = item.data(Qt.ItemDataRole.UserRole + 1)
        if not data:
            return
            
        parts = data["parts"]
        
        # Calculate selected tender's remaining balance (Unpaid parts where index 13 is not 1.0)
        selected_remaining = 0.0
        for p in parts:
            if not (len(p) > 13 and p[13] == 1.0):
                selected_remaining += float(p[6] or 0.0)
        self.detail_total_label.setText(f"<b>Seçili İhalede Bekleyen Alacak: {format_money(selected_remaining)} TL</b>")

        # Sort by Parti No (index 4) safely
        parts.sort(key=lambda x: int(x[4]) if str(x[4]).isdigit() else 0)
        
        self.part_table.setRowCount(len(parts))
        for i, p in enumerate(parts):
            # p structure indexes: 4=PartiNo, 5=Tarih, 6=Tutar, 11=Kabul, 14=Aciklama
            
            # Parti No
            self.part_table.setItem(i, 0, QTableWidgetItem(str(p[4])))
            
            # Tarih
            tarih_str = format_date_tr(str(p[5]))
            self.part_table.setItem(i, 1, QTableWidgetItem(tarih_str))
            
            # Miktar
            miktar_val = str(p[16]) if len(p) > 16 and p[16] else ""
            m_item = QTableWidgetItem(miktar_val)
            m_item.setTextAlignment(Qt.AlignCenter)
            self.part_table.setItem(i, 2, m_item)
            
            # Tutar
            tutar_str = format_money(p[6]) + " TL"
            tutar_item = QTableWidgetItem(tutar_str)
            tutar_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.part_table.setItem(i, 3, tutar_item)
            
            # Durum
            status = "Bekliyor"
            if len(p) > 13 and p[13] == 1.0:
                status = "Tamamlandı"
            
            status_item = QTableWidgetItem(status)
            if status == "Tamamlandı":
                is_dark = self.parent_window.is_dark_mode if self.parent_window else False
                status_item.setForeground(QColor("#4ade80" if is_dark else "#16a34a"))
                status_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.part_table.setItem(i, 4, status_item)
            
            # Açıklama
            desc = str(p[14]) if len(p) > 14 and p[14] else ""
            self.part_table.setItem(i, 5, QTableWidgetItem(desc))

# --- FIRMA ÖZETLERİ SEKME ---
class FirmSummaryWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Filter Layout (Search + Year)
        filter_layout = QHBoxLayout()
        
        filter_layout.addWidget(QLabel("🔍 Firma Ara:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Firma ismi yazın...")
        self.search_edit.textChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.search_edit)
        
        filter_layout.addSpacing(20)
        
        filter_layout.addWidget(QLabel("📅 Yıl:"))
        self.cb_year = QComboBox()
        self.cb_year.setView(QListView())
        self.cb_year.setItemDelegate(DropdownDelegate())
        self.cb_year.addItem("Tümü")
        self.cb_year.currentTextChanged.connect(self.refresh_data)
        filter_layout.addWidget(self.cb_year)
        
        filter_layout.addSpacing(10)
        self.btn_clear = QPushButton("Temizle")
        self.btn_clear.clicked.connect(self.clear_filters)
        filter_layout.addWidget(self.btn_clear)
        
        filter_layout.addStretch()
        
        self.total_label = QLabel("<b>GENEL TOPLAM: 0,00 TL</b>")
        is_dark = self.parent_window.is_dark_mode if self.parent_window else False
        lbl_bg = "#1e293b" if is_dark else "#f1f5f9"
        self.total_label.setStyleSheet(f"font-size: 14px; color: #6366f1; background-color: {lbl_bg}; padding: 5px 12px; border-radius: 6px; border: 1px solid #6366f1;")
        filter_layout.addWidget(self.total_label)

        layout.addLayout(filter_layout)
        
        # Table
        self.table = QTableWidget()
        self.table.setAlternatingRowColors(True)
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Yüklenici Firma", "İhale Sayısı", "Toplam Parti Sayısı", "Toplam Tutar (TL)"])
        self.table.setSortingEnabled(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        layout.addWidget(self.table)
        self.refresh_data()

    def refresh_data(self):
        # Yıl listesini güncelle (sadece ilk kez veya veri değiştiğinde)
        if self.cb_year.count() <= 1:
            rows = fetch_data()
            years = sorted(list(set(r[5][:4] for r in rows if r[5])), reverse=True)
            self.cb_year.blockSignals(True)
            self.cb_year.clear()
            self.cb_year.addItem("Tümü")
            self.cb_year.addItems(years)
            self.cb_year.blockSignals(False)

        self.table.blockSignals(True)
        selected_year = self.cb_year.currentText()
        self.all_firms = get_firm_summary_data(selected_year)
        self.apply_filter()
        self.table.blockSignals(False)

    def clear_filters(self):
        self.search_edit.clear()
        self.cb_year.setCurrentIndex(0)
        self.refresh_data()

    def apply_filter(self):
        txt = self.search_edit.text().lower()
        filtered = [f for f in self.all_firms if not txt or txt in f["name"].lower()]
        
        # Update Grand Total
        grand_total = sum(f["volume"] for f in filtered)
        self.total_label.setText(f"<b>GENEL TOPLAM: {format_money(grand_total)} TL</b>")
        
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(filtered))
        
        for i, f in enumerate(filtered):
            # Name
            self.table.setItem(i, 0, QTableWidgetItem(f["name"]))
            
            # Tender Count
            t_item = SortableTableWidgetItem(str(f["tender_count"]))
            t_item.setData(Qt.ItemDataRole.UserRole, f["tender_count"])
            t_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(i, 1, t_item)
            
            # Part Count
            c_item = SortableTableWidgetItem(str(f["part_count"]))
            c_item.setData(Qt.ItemDataRole.UserRole, f["part_count"])
            c_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(i, 2, c_item)
            
            # Total Volume
            v_item = SortableTableWidgetItem(format_money(f["volume"]) + " TL")
            v_item.setData(Qt.ItemDataRole.UserRole, f["volume"])
            v_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.table.setItem(i, 3, v_item)
            
        self.table.setSortingEnabled(True)

# --- ÖZEL TAKVİM BİLEŞENİ ---
class CustomCalendar(QCalendarWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.date_counts = {} # {QDate: count}

    def set_date_counts(self, counts):
        self.date_counts = counts
        self.update()

    def paintCell(self, painter, rect, date):
        super().paintCell(painter, rect, date)
        
        if date in self.date_counts:
            count = self.date_counts[date]
            if count > 0:
                painter.save()
                # Badge çizimi
                badge_size = 18
                badge_rect = rect.adjusted(rect.width() - badge_size - 2, 2, -2, -(rect.height() - badge_size - 2))
                
                painter.setRenderHint(QPainter.RenderHint.Antialiasing)
                painter.setBrush(QBrush(QColor("#6366f1")))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.drawEllipse(badge_rect)
                
                painter.setPen(QColor("white"))
                font = painter.font()
                font.setPointSize(8)
                font.setBold(True)
                painter.setFont(font)
                painter.drawText(badge_rect, Qt.AlignCenter, str(count))
                painter.restore()

# --- TAKVİM SAYFASI ---
class CalendarWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.all_data = []
        self.setup_ui()
        self.refresh_data()

    def setup_ui(self):
        layout = QHBoxLayout(self)
        
        # Sol Panel: Takvim ve Filtreler
        left_panel = QVBoxLayout()
        left_panel.setContentsMargins(10, 10, 10, 10)
        
        title_layout = QHBoxLayout()
        title = QLabel("📅 Teslimat Takvimi")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #5e35b1;")
        title_layout.addWidget(title)
        
        title_layout.addStretch()
        
        self.btn_today = QPushButton("🎯 Bugün")
        self.btn_today.setFixedWidth(100)
        self.btn_today.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_today.setStyleSheet("""
            QPushButton { 
                background-color: #6366f1; color: white; border-radius: 6px; padding: 5px; font-weight: bold;
            }
            QPushButton:hover { background-color: #4f46e5; }
        """)
        self.btn_today.clicked.connect(self.go_to_today)
        title_layout.addWidget(self.btn_today)
        
        left_panel.addLayout(title_layout)
        left_panel.addSpacing(5)

        # Takvim Görünümü
        self.calendar = CustomCalendar()
        self.calendar.setGridVisible(True)
        self.calendar.setVerticalHeaderFormat(QCalendarWidget.VerticalHeaderFormat.NoVerticalHeader)
        self.calendar.selectionChanged.connect(self.date_selected)
        
        # Takvim boyutunu artır
        self.calendar.setMinimumHeight(450)
        
        # Takvim stilini modernleştir
        # Ay/Yıl butonlarını beyaz yapmak için: QToolButton renkleri
        self.calendar.setStyleSheet("""
            QCalendarWidget QWidget { alternate-background-color: #f1f5f9; }
            QCalendarWidget QAbstractItemView:enabled { color: #1e293b; selection-background-color: #6366f1; selection-color: white; }
            QCalendarWidget QToolButton { 
                color: white; 
                background-color: #6366f1;
                font-weight: bold; 
                border-radius: 4px;
                margin: 2px;
                padding: 2px 10px;
            }
            QCalendarWidget QToolButton:hover { background-color: #4f46e5; }
            QCalendarWidget QToolButton::menu-indicator { image: none; }
            QCalendarWidget QWidget#qt_calendar_navigationbar { background-color: #5e35b1; }
            QCalendarWidget QMenu { background-color: white; }
            QCalendarWidget QSpinBox { width: 60px; font-size: 14px; background-color: white; color: #1e293b; }
        """)
        
        left_panel.addWidget(self.calendar)
        
        # Filtreler
        self.filter_box = QFrame()
        self.filter_box.setObjectName("FilterBox")
        is_dark = self.parent_window.is_dark_mode if self.parent_window else False
        box_bg = "#1e293b" if is_dark else "#f8fafc"
        box_border = "#334155" if is_dark else "#e2e8f0"
        self.filter_box.setStyleSheet(f"#FilterBox {{ background-color: {box_bg}; border-radius: 8px; border: 1px solid {box_border}; padding: 10px; }}")
        f_layout = QVBoxLayout(self.filter_box)
        
        f_layout.addWidget(QLabel("<b>Görünüm Filtresi:</b>"))
        self.cb_status = QComboBox()
        self.cb_status.setView(QListView())
        self.cb_status.setItemDelegate(DropdownDelegate())
        self.cb_status.addItems(["Tüm Teslimatlar", "Sadece Bekleyenler", "Sadece Tamamlananlar"])
        self.cb_status.currentTextChanged.connect(self.refresh_data)
        f_layout.addWidget(self.cb_status)
        
        left_panel.addWidget(self.filter_box)
        left_panel.addSpacing(10)
        
        # Aylık Özet
        self.summary_box = QFrame()
        self.summary_box.setObjectName("SummaryBox")
        is_dark = self.parent_window.is_dark_mode if self.parent_window else False
        box_bg = "#1e293b" if is_dark else "#f8fafc"
        box_border = "#334155" if is_dark else "#e2e8f0"
        self.summary_box.setStyleSheet(f"#SummaryBox {{ background-color: {box_bg}; border-radius: 8px; border: 1px solid {box_border}; padding: 10px; }}")
        s_layout = QVBoxLayout(self.summary_box)
        
        self.lbl_month_title = QLabel("📊 Aylık Özet")
        self.lbl_month_title.setStyleSheet("font-weight: bold; color: #5e35b1; font-size: 14px;")
        s_layout.addWidget(self.lbl_month_title)
        
        self.lbl_month_total = QLabel("💰 Toplam Tutar: 0,00 TL")
        self.lbl_month_firms = QLabel("🏢 Firma Sayısı: 0")
        self.lbl_month_tenders = QLabel("📋 Toplam İhale: 0")
        self.lbl_month_batches = QLabel("📦 Toplam Parti: 0")
        
        for lbl in [self.lbl_month_total, self.lbl_month_firms, self.lbl_month_tenders, self.lbl_month_batches]:
            lbl.setStyleSheet(f"color: {'#f8fafc' if is_dark else '#1e293b'}; font-size: 13px;")
            s_layout.addWidget(lbl)
            
        left_panel.addWidget(self.summary_box)
        left_panel.addStretch()
        
        # Sayfa (Ay) değiştiğinde özeti güncelle
        self.calendar.currentPageChanged.connect(self.update_monthly_summary)
        
        layout.addLayout(left_panel, stretch=1)
        
        # Sağ Panel: Günlük Detaylar
        right_panel = QVBoxLayout()
        right_panel.setContentsMargins(10, 10, 10, 10)
        
        self.detail_label = QLabel("Seçili Tarihteki İşler")
        self.detail_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #5e35b1;")
        right_panel.addWidget(self.detail_label)
        
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.card_container = QWidget()
        self.card_layout = QVBoxLayout(self.card_container)
        self.card_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.scroll.setWidget(self.card_container)
        right_panel.addWidget(self.scroll)
        
        layout.addLayout(right_panel, stretch=2)

    def go_to_today(self):
        self.calendar.setSelectedDate(QDate.currentDate())
        self.calendar.showToday()

    def refresh_data(self):
        self.all_data = fetch_data()
        self.update_calendar_styles()
        self.highlight_dates()
        self.date_selected()
        self.update_monthly_summary() # Özeti güncelle

    def update_monthly_summary(self):
        # Şu an gösterilen ay ve yılı al
        year = self.calendar.yearShown()
        month = self.calendar.monthShown()
        
        total_amount = 0.0
        firms = set()
        tenders = set()
        batch_count = 0
        
        filter_mode = self.cb_status.currentText()
        
        for r in self.all_data:
            if not r[5]: continue
            
            # Veritabanındaki tarih: yyyy-mm-dd
            try:
                qdate = QDate.fromString(r[5][:10], "yyyy-MM-dd")
                if qdate.year() == year and qdate.month() == month:
                    is_completed = (len(r) > 11 and r[11] == 1.0)
                    
                    if filter_mode == "Sadece Bekleyenler" and is_completed: continue
                    if filter_mode == "Sadece Tamamlananlar" and not is_completed: continue
                    
                    total_amount += parse_money(r[6])
                    firms.add(r[2])
                    tenders.add(r[1]) # IKN
                    batch_count += 1
            except:
                continue
        
        # UI Güncelleme
        self.lbl_month_total.setText(f"💰 Toplam Tutar: {format_money(str(total_amount))} TL")
        self.lbl_month_firms.setText(f"🏢 Firma Sayısı: {len(firms)}")
        self.lbl_month_tenders.setText(f"📋 Toplam İhale: {len(tenders)}")
        self.lbl_month_batches.setText(f"📦 Toplam Parti: {batch_count}")
        
        # Başlığı gösterilen aya göre güncelle
        tr_months = ["", "Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran", "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık"]
        self.lbl_month_title.setText(f"📊 {tr_months[month]} {year} Özeti")

    def update_calendar_styles(self):
        is_dark = self.parent_window.is_dark_mode if self.parent_window else False
        
        # Ana Takvim Stili
        bg_color = "#1e293b" if is_dark else "#ffffff"
        text_color = "#f8fafc" if is_dark else "#1e293b"
        header_bg = "#5e35b1"
        grid_color = "#334155" if is_dark else "#e2e8f0"
        alt_bg = "#334155" if is_dark else "#f1f5f9"
        
        self.calendar.setStyleSheet(f"""
            QCalendarWidget QWidget {{ 
                alternate-background-color: {alt_bg}; 
                background-color: {bg_color};
            }}
            QCalendarWidget QAbstractItemView:enabled {{ 
                color: {text_color}; 
                selection-background-color: #000000; 
                selection-color: #ffffff; 
            }}
            QCalendarWidget QAbstractItemView:disabled {{ color: #475569; }}
            QCalendarWidget QToolButton {{ 
                color: white; 
                background-color: #6366f1;
                font-weight: bold; 
                border-radius: 4px;
                margin: 2px;
                padding: 2px 10px;
            }}
            QCalendarWidget QToolButton:hover {{ background-color: #4f46e5; }}
            QCalendarWidget QToolButton::menu-indicator {{ image: none; }}
            QCalendarWidget QWidget#qt_calendar_navigationbar {{ background-color: {header_bg}; }}
            QCalendarWidget QMenu {{ background-color: {bg_color}; color: {text_color}; }}
            QCalendarWidget QMenu::item:selected {{ background-color: #6366f1; color: white; }}
            QCalendarWidget QSpinBox {{ 
                width: 120px; font-size: 15px; 
                background-color: {bg_color}; color: {text_color};
                border: 1px solid {grid_color};
                selection-background-color: #6366f1;
                border-radius: 4px;
                padding-right: 20px; /* Make room for buttons if needed, though they are outside content usually */
            }}
            QCalendarWidget QSpinBox::up-button {{ 
                subcontrol-origin: border; 
                subcontrol-position: top right;
                width: 30px; 
                background-color: #6366f1; 
                border-left: 1px solid {grid_color};
                border-bottom: 1px solid {grid_color}; 
                border-top-right-radius: 4px;
                image: url(data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAyNCAyNCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBkPSZNMTIgOGwtNiA2aDEyeiIgZmlsbD0id2hpdGUiLz48L3N2Zz4=);
            }}
            QCalendarWidget QSpinBox::down-button {{ 
                subcontrol-origin: border; 
                subcontrol-position: bottom right;
                width: 30px; 
                background-color: #6366f1; 
                border-left: 1px solid {grid_color};
                border-top: 1px solid {grid_color};
                border-bottom-right-radius: 4px;
                image: url(data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAyNCAyNCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCBkPSZNMTIgMTZsLTYtNmgxMnoiIGZpbGw9IndoaXRlIi8+PC9zdmc+);
            }}
            QCalendarWidget QSpinBox::up-arrow {{ image: none; width: 0; height: 0; }}
            QCalendarWidget QSpinBox::down-arrow {{ image: none; width: 0; height: 0; }}
        """)
        
        # Kutuları güncelle (Sol Panel)
        box_bg = "#1e293b" if is_dark else "#f8fafc"
        box_border = "#334155" if is_dark else "#e2e8f0"
        self.filter_box.setStyleSheet(f"#FilterBox {{ background-color: {box_bg}; border-radius: 8px; border: 1px solid {box_border}; padding: 10px; }}")
        self.summary_box.setStyleSheet(f"#SummaryBox {{ background-color: {box_bg}; border-radius: 8px; border: 1px solid {box_border}; padding: 10px; }}")
        
        for lbl in [self.lbl_month_total, self.lbl_month_firms, self.lbl_month_tenders, self.lbl_month_batches]:
            lbl.setStyleSheet(f"color: {'#f8fafc' if is_dark else '#1e293b'}; font-size: 13px;")

    def highlight_dates(self):
        self.calendar.setDateTextFormat(QDate(), QTextCharFormat())
        
        filter_mode = self.cb_status.currentText()
        is_dark = self.parent_window.is_dark_mode if self.parent_window else False
        
        counts = {}
        
        for r in self.all_data:
            if not r[5]: continue
            
            is_completed = (len(r) > 11 and r[11] == 1.0)
            
            if filter_mode == "Sadece Bekleyenler" and is_completed: continue
            if filter_mode == "Sadece Tamamlananlar" and not is_completed: continue
            
            day_str = r[5][:10]
            qdate = QDate.fromString(day_str, "yyyy-MM-dd")
            if not qdate.isValid(): continue
            
            # Count for badges
            counts[qdate] = counts.get(qdate, 0) + 1
            
            fmt = QTextCharFormat()
            color_str = get_date_color(day_str, is_completed)
            if color_str:
                fmt.setBackground(QColor(color_str))
                fmt.setForeground(QColor("white"))
            else:
                if is_completed:
                    fmt.setBackground(QColor("#4ade80" if is_dark else "#16a34a"))
                else:
                    fmt.setBackground(QColor("#6366f1"))
                fmt.setForeground(QColor("white"))
            
            fmt.setFontWeight(QFont.Weight.Bold)
            self.calendar.setDateTextFormat(qdate, fmt)
            
        self.calendar.set_date_counts(counts)

    def date_selected(self):
        # Ekrandaki kartları temizle
        while self.card_layout.count():
            item = self.card_layout.takeAt(0)
            if item.widget(): item.widget().deleteLater()
            
        selected_qdate = self.calendar.selectedDate()
        date_str = selected_qdate.toString("yyyy-MM-dd")
        self.detail_label.setText(f"📅 {selected_qdate.toString('dd.MM.yyyy')} Tarihindeki İşler")
        
        filter_mode = self.cb_status.currentText()
        
        found_data = []
        for r in self.all_data:
            if r[5] and r[5][:10] == date_str:
                is_completed = (len(r) > 11 and r[11] == 1.0)
                if filter_mode == "Sadece Bekleyenler" and is_completed: continue
                if filter_mode == "Sadece Tamamlananlar" and not is_completed: continue
                found_data.append(r)
        
        if found_data:
            for r in found_data:
                # SummaryWidget'taki create_card fonksiyonunu kullanalım
                card = self.parent_window.summary_widget.create_card(r)
                self.card_layout.addWidget(card)
        else:
            empty_lbl = QLabel("Bu tarihte planlanmış bir teslimat bulunmuyor. 🏖️")
            empty_lbl.setAlignment(Qt.AlignCenter)
            empty_lbl.setStyleSheet("font-size: 14px; color: #64748b; margin-top: 50px;")
            self.card_layout.addWidget(empty_lbl)

class DetailWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.current_status_filter = "all" # all, active, completed
        self.setup_ui()
        self.refresh_data()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Üst Buton Paneli
        top_btn_layout = QHBoxLayout()
        btn_new = QPushButton("➕ Yeni İhale Ekle")
        btn_new.setObjectName("SuccessBtn")
        btn_new.clicked.connect(self.open_new_tender)
        top_btn_layout.addWidget(btn_new)

        btn_new_batch = QPushButton("📦 Yeni Parti Bilgisi Ekle")
        btn_new_batch.setObjectName("SuccessBtn")
        btn_new_batch.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_new_batch.clicked.connect(self.open_new_batch)
        top_btn_layout.addWidget(btn_new_batch)

        btn_export = QPushButton("📊 Verileri CSV Olarak Dışa Aktar")
        btn_export.setObjectName("InfoBtn")
        btn_export.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_export.clicked.connect(self.export_to_csv)
        top_btn_layout.addWidget(btn_export)

        btn_backup = QPushButton("💾 Güncel Verinin Yedeğini Al")
        btn_backup.setObjectName("InfoBtn")
        btn_backup.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_backup.clicked.connect(self.backup_now)
        top_btn_layout.addWidget(btn_backup)

        btn_col_settings = QPushButton("⚙️ Sütun Ayarları")
        btn_col_settings.setObjectName("PrimaryBtn")
        btn_col_settings.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_col_settings.clicked.connect(self.show_column_settings)
        top_btn_layout.addWidget(btn_col_settings)

        # Spacer between Actions and Filters
        top_btn_layout.addSpacing(40)

        # Durum Filtre Butonları
        self.btn_all = QPushButton("Tüm İşler")
        self.btn_active = QPushButton("Devam Edenler")
        self.btn_completed = QPushButton("Tamamlananlar")
        
        for btn in [self.btn_all, self.btn_active, self.btn_completed]:
            btn.setCheckable(True)
            btn.setStyleSheet("""
                QPushButton { background-color: #cbd5e1; color: #1e293b; border: 1px solid #94a3b8; padding: 6px; border-radius: 6px; }
                QPushButton:hover { background-color: #94a3b8; }
                QPushButton:checked { background-color: #6366f1; color: white; border: 1px solid #6366f1; }
                QPushButton:checked:hover { background-color: #4f46e5; }
            """)
            top_btn_layout.addWidget(btn)
        
        top_btn_layout.addStretch()
        layout.addLayout(top_btn_layout)
        
        self.btn_all.setChecked(True)
        self.btn_all.clicked.connect(lambda: self.set_status_filter("all"))
        self.btn_active.clicked.connect(lambda: self.set_status_filter("active"))
        self.btn_completed.clicked.connect(lambda: self.set_status_filter("completed"))

        # Filtre Paneli
        f_panel = QHBoxLayout()
        self.search = QLineEdit(); self.search.setPlaceholderText("Metin ara...")
        btn_clr = QPushButton("Temizle"); btn_clr.clicked.connect(self.clear_filters)
        
        self.cb_date_filter = QCheckBox("Tarih Filtresi:")
        self.date_start = QDateEdit()
        self.date_start.setCalendarPopup(True)
        self.date_start.setDate(QDate.currentDate().addMonths(-6))
        self.date_end = QDateEdit()
        self.date_end.setCalendarPopup(True)
        self.date_end.setDate(QDate.currentDate().addMonths(6))
        self.date_sep_label = QLabel("-")
        
        # Başlangıçta gizli
        self.date_start.setVisible(False)
        self.date_sep_label.setVisible(False)
        self.date_end.setVisible(False)
        
        self.cb_date_filter.stateChanged.connect(self.apply_filters)
        self.cb_date_filter.toggled.connect(self.toggle_date_filter_visibility)
        self.date_start.dateChanged.connect(self.apply_filters)
        self.date_end.dateChanged.connect(self.apply_filters)
        
        self.cb_firm = QComboBox(); self.cb_firm.setView(QListView()); self.cb_firm.setItemDelegate(DropdownDelegate()); self.cb_firm.setMinimumWidth(180); self.cb_firm.currentTextChanged.connect(self.firm_changed)
        self.cb_tender = QComboBox(); self.cb_tender.setView(QListView()); self.cb_tender.setItemDelegate(DropdownDelegate()); self.cb_tender.setMinimumWidth(180); self.cb_tender.currentTextChanged.connect(self.apply_filters)
        
        f_panel.addWidget(QLabel("Ara:")); f_panel.addWidget(self.search, stretch=1); f_panel.addWidget(btn_clr)
        f_panel.addSpacing(15); f_panel.addWidget(self.cb_date_filter)
        f_panel.addWidget(self.date_start); f_panel.addWidget(self.date_sep_label); f_panel.addWidget(self.date_end)
        f_panel.addSpacing(15); f_panel.addWidget(QLabel("Firma:")); f_panel.addWidget(self.cb_firm, stretch=1)
        f_panel.addWidget(QLabel("İhale:")); f_panel.addWidget(self.cb_tender, stretch=1)
        layout.addLayout(f_panel)
        
        self.search.textChanged.connect(self.apply_filters)
        self.table = QTableWidget(); self.table.setColumnCount(18)
        self.table.setAlternatingRowColors(True)
        self.table.setHorizontalHeaderLabels([
            "IKN", "Firma", "İhale Adı", "Sözl. Tarihi", "Parti", "Parti Tarihi",
            "Miktar", "Malzeme Detayı", "Tutar",
            "Ambar", "Bşk. Haber", "Test B.", "Test S.", "Rapor", "Kabul", "Ödeme",
            "Açıklama", "İşlem"
        ])

        # Sütun Genişlikleri
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(0, 100)  # IKN
        self.table.setColumnWidth(1, 150)  # Firma
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)  # Ihale Adi
        self.table.setColumnWidth(3, 110)  # Sozlesme Tarihi
        self.table.setColumnWidth(4, 60)   # Parti
        self.table.setColumnWidth(5, 90)   # Tarih
        self.table.setColumnWidth(6, 80)   # Miktar
        self.table.setColumnWidth(7, 200)  # Malzeme Detayi
        self.table.setColumnWidth(8, 120)  # Tutar
        # Durum Sütunları (Ambar, Test B., Test S., Rapor, Kabul, Heyet, Ödeme)
        for i in range(9, 16):
            self.table.setColumnWidth(i, 80)
        self.table.setColumnWidth(16, 200)  # Aciklama
        self.table.setColumnWidth(17, 130)  # Islem

        self.table.setSortingEnabled(True)
        
        # Toplu işlem için çoklu seçim ve sağ menü
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        
        layout.addWidget(self.table)
        # Kaydedilmiş sütun görünürlüğü ayarlarını yükle
        self.load_column_settings()
    def toggle_date_filter_visibility(self, checked):
        self.date_start.setVisible(checked)
        self.date_sep_label.setVisible(checked)
        self.date_end.setVisible(checked)

    def export_to_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Verileri CSV Olarak Kaydet", "", "CSV Dosyası (*.csv)")
        if not path:
            return
            
        try:
            # Table visualization column count minus the "İşlem" column
            col_count = self.table.columnCount() - 1
            headers = [self.table.horizontalHeaderItem(i).text() for i in range(col_count)]
            
            with open(path, mode='w', encoding='utf-8-sig', newline='') as file:
                writer = csv.writer(file, delimiter=';')
                writer.writerow(headers)
                
                for row in range(self.table.rowCount()):
                    row_data = []
                    for col in range(col_count):
                        item = self.table.item(row, col)
                        row_data.append(item.text() if item else "")
                    writer.writerow(row_data)
            
            QMessageBox.information(self, "Başarılı", f"Veriler başarıyla dışa aktarıldı:\n{path}")
            log_action("CSV Dışa Aktar", f"Dosya: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"CSV dışa aktarma hatası:\n{e}")
            
    def refresh_data(self):
        # Mevcut seçimleri kaydet
        current_firm = self.cb_firm.currentText()
        current_tender = self.cb_tender.currentText()
        
        self.all_data = fetch_data()
        
        # Dropdownları güncelle (seçimleri koruyarak)
        self.update_firm_dropdown(current_firm, current_tender)

    def get_status_filtered_data(self):
        # 1. Adım: Durum filtresine göre veriyi daralt
        if self.current_status_filter == "all":
            return self.all_data
        
        filtered = []
        for r in self.all_data:
            # Kabul Yapildi -> index 11
            is_completed = (len(r) > 11 and r[11] == 1.0)
            if self.current_status_filter == "active" and not is_completed:
                 filtered.append(r)
            elif self.current_status_filter == "completed" and is_completed:
                 filtered.append(r)
        return filtered

    def update_firm_dropdown(self, preserve_firm=None, preserve_tender=None):
        # Eğer dışarıdan belirli bir firma korunmak isteniyorsa onu kullan, yoksa mevcut olana bak
        current = preserve_firm if preserve_firm else self.cb_firm.currentText()
        
        data_source = self.get_status_filtered_data()
        
        self.cb_firm.blockSignals(True)
        self.cb_firm.clear()
        self.cb_firm.addItem("Tümü")
        
        firms = sorted(list(set(str(r[2]) for r in data_source)), key=tr_key)
        self.cb_firm.addItems(firms)
        
        if current in firms:
            self.cb_firm.setCurrentText(current)
        else:
            self.cb_firm.setCurrentIndex(0)
            
        self.cb_firm.blockSignals(False)
        self.firm_changed(preserve_tender)

    def firm_changed(self, preserve_tender=None):
        # Eğer dışarıdan belirli bir ihale korunmak isteniyorsa onu kullan, yoksa mevcut olana bak
        current_tender = preserve_tender if preserve_tender else self.cb_tender.currentText()
        
        data_source = self.get_status_filtered_data()
        
        self.cb_tender.blockSignals(True)
        self.cb_tender.clear()
        self.cb_tender.addItem("Tümü")
        
        firm = self.cb_firm.currentText()
        
        # Seçili firmaya göre ihaleleri filtrele
        tenders = sorted(list(set(str(r[3]) for r in data_source if firm == "Tümü" or str(r[2]) == firm)), key=tr_key)
        self.cb_tender.addItems(tenders)
        
        if current_tender in tenders:
            self.cb_tender.setCurrentText(current_tender)
        
        self.cb_tender.blockSignals(False)
        self.apply_filters() # Tabloyu güncelle

    def set_status_filter(self, mode):
        self.current_status_filter = mode
        self.btn_all.setChecked(mode == "all")
        self.btn_active.setChecked(mode == "active")
        self.btn_completed.setChecked(mode == "completed")
        # Butona basılınca dropdownları da güncelle
        self.update_firm_dropdown()

    def apply_filters(self):
        txt = self.search.text().lower()
        f = self.cb_firm.currentText(); t = self.cb_tender.currentText()
        
        use_date_filter = self.cb_date_filter.isChecked()
        d_start = self.date_start.date().toString("yyyy-MM-dd")
        d_end = self.date_end.date().toString("yyyy-MM-dd")
        
        # Filtreleme Mantığı
        filtered = []
        for r in self.all_data:
            # Metin, Firma, İhale Filtresi
            basic_match = (f == "Tümü" or str(r[2]) == f) and \
                          (t == "Tümü" or str(r[3]) == t) and \
                          (not txt or txt in str(r).lower())
            
            if not basic_match:
                continue
                
            if use_date_filter:
                tarih_raw = str(r[5])[:10] if r[5] else ""
                if not tarih_raw or not (d_start <= tarih_raw <= d_end):
                    continue
                
            # Durum Filtresi (Kabul Yapildi -> index 11)
            is_completed = (len(r) > 11 and r[11] == 1.0)
            if self.current_status_filter == "active" and is_completed:
                continue
            if self.current_status_filter == "completed" and not is_completed:
                continue
                
            filtered.append(r)
        
        self.table.setSortingEnabled(False) # Veri eklerken sıralamayı kapat
        self.table.setRowCount(len(filtered))
        for row_idx, r in enumerate(filtered):
            # IKN, Firma, Ihale Adi (Standart String)
            for i in range(3): 
                item = QTableWidgetItem(str(r[i+1]))
                if i == 0:
                    item.setData(Qt.ItemDataRole.UserRole, r[0])
                self.table.setItem(row_idx, i, item)
            
            # Sözleşme Tarihi
            sozlesme_raw = str(r[17])[:10] if len(r) > 17 and r[17] else ""
            sozlesme_item = QTableWidgetItem(format_date_tr(sozlesme_raw))
            sozlesme_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row_idx, 3, sozlesme_item)

            # Parti No (Sayısal Sıralama)
            parti_val = 0
            try:
                parti_val = int(r[4])
            except: pass
            
            parti_item = SortableTableWidgetItem(str(r[4]))
            parti_item.setData(Qt.ItemDataRole.UserRole, parti_val)
            parti_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row_idx, 4, parti_item)

            # Tarih
            tarih_raw = str(r[5])[:10] if r[5] else ""
            tarih_display = format_date_tr(tarih_raw)
            tarih_item = SortableTableWidgetItem(tarih_display)
            tarih_item.setData(Qt.ItemDataRole.UserRole, tarih_raw)
            tarih_item.setTextAlignment(Qt.AlignCenter)
            
            is_completed = (len(r) > 11 and r[11] == 1.0)
            date_color = get_date_color(tarih_raw, is_completed)
            if date_color:
                tarih_item.setBackground(QColor(date_color))
                tarih_item.setForeground(QColor("white"))
                
            self.table.setItem(row_idx, 5, tarih_item)
            
            # Miktar
            miktar_val = str(r[16]) if len(r) > 16 and r[16] else ""
            m_item = QTableWidgetItem(miktar_val)
            m_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row_idx, 6, m_item)

            # Malzeme Detayı (index 18 in record)
            malzeme_val = str(r[18]) if len(r) > 18 and r[18] else ""
            mal_item = QTableWidgetItem(malzeme_val)
            mal_item.setToolTip(malzeme_val)  # uzun metinler için tooltip
            self.table.setItem(row_idx, 7, mal_item)

            # Tutar (now col 8)
            t_item = SortableTableWidgetItem(f"{format_money(r[6])} TL")
            t_item.setData(Qt.ItemDataRole.UserRole, float(r[6]) if r[6] else 0.0)
            t_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.table.setItem(row_idx, 8, t_item)

            # Durum sütunları (cols 9-15)
            for c, idx in enumerate([7, 19, 8, 9, 10, 11, 13], 9):
                val = r[idx] if idx < len(r) else 0.0
                it = QTableWidgetItem("✓" if val == 1.0 else "○")
                it.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row_idx, c, it)

            # Açıklama (col 16)
            self.table.setItem(row_idx, 16, QTableWidgetItem(str(r[14]) if len(r) > 14 else ""))

            # İşlem Butonları (col 17)
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(0, 0, 0, 0)
            action_layout.setSpacing(5)

            btn_edit = QPushButton("Düzenle")
            btn_edit.setStyleSheet("background-color: #ff9800; color: white; border-radius: 4px; padding: 4px;")
            btn_edit.clicked.connect(lambda ch, rec=r: self.open_edit(rec))
            action_layout.addWidget(btn_edit)

            if CURRENT_USER_ROLE == "admin":
                btn_delete = QPushButton("Sil")
                btn_delete.setStyleSheet("background-color: #d32f2f; color: white; border-radius: 4px; padding: 4px;")
                btn_delete.clicked.connect(lambda ch, rec=r: self.delete_row(rec))
                action_layout.addWidget(btn_delete)

            action_layout.addStretch()
            self.table.setCellWidget(row_idx, 17, action_widget)
            
        self.table.setSortingEnabled(True)  # Sıralamayı tekrar aç

    # --------------------------------------------------------
    # YEDEKLEME
    # --------------------------------------------------------
    def backup_now(self):
        """Kullanıcı tarafından tetiklenen anlık yedekleme."""
        try:
            if getattr(sys, 'frozen', False):
                base_path = os.path.dirname(sys.executable)
            else:
                base_path = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(base_path, 'veriler.db')
            backup_dir = os.path.join(base_path, 'Yedekler')
            os.makedirs(backup_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            backup_file = os.path.join(backup_dir, f"veriler_yedek_{timestamp}.db")
            shutil.copy(db_path, backup_file)
            log_action("Manuel Yedekleme", f"Dosya: {backup_file}")
            QMessageBox.information(self, "Yedek Alındı",
                f"İşlem başarılı!\nYedek dosyası oluşturuldu:\n{backup_file}")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Yedekleme sırasında hata oluştu:\n{e}")

    # --------------------------------------------------------
    # SUTUN AYARLARI
    # --------------------------------------------------------
    def show_column_settings(self):
        """Sütun görünürlüğü seçim diyaloğu."""
        dlg = QDialog(self)
        dlg.setWindowTitle("⚙️ Sütun Ayarları")
        dlg.setFixedWidth(300)
        layout = QVBoxLayout(dlg)
        layout.addWidget(QLabel("<b>Gösterilecek Sütunları Seçin:</b>"))

        # Son sütun (İşlem) her zaman görünür; ona checkbox vermiyoruz
        checkboxes = []
        for col in range(self.table.columnCount() - 1):
            header_item = self.table.horizontalHeaderItem(col)
            label = header_item.text() if header_item else f"Sütun {col}"
            cb = QCheckBox(label)
            cb.setChecked(not self.table.isColumnHidden(col))
            layout.addWidget(cb)
            checkboxes.append((col, cb))

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.button(QDialogButtonBox.StandardButton.Ok).setText("Uygula")
        btns.button(QDialogButtonBox.StandardButton.Cancel).setText("İptal")
        btns.accepted.connect(dlg.accept)
        btns.rejected.connect(dlg.reject)
        layout.addWidget(btns)

        if dlg.exec():
            for col, cb in checkboxes:
                self.table.setColumnHidden(col, not cb.isChecked())
            self.save_column_settings()

    def save_column_settings(self):
        """Sütun görünürlüğünü kullanıcıya özel olarak kaydeder."""
        settings = QSettings("IhaleSystem", f"UserPrefs/{CURRENT_USER}")
        hidden = []
        for col in range(self.table.columnCount()):
            if self.table.isColumnHidden(col):
                hidden.append(col)
        settings.setValue("detail_hidden_cols", hidden)

    def load_column_settings(self):
        """Kaydedilmiş sütun görünürlüğünü yükler."""
        settings = QSettings("IhaleSystem", f"UserPrefs/{CURRENT_USER}")
        hidden = settings.value("detail_hidden_cols", [])
        if hidden:
            for col in hidden:
                try:
                    self.table.setColumnHidden(int(col), True)
                except:
                    pass

    def open_new_tender(self):
        if NewTenderDialog(self).exec(): self.parent_window.refresh_all()

    def open_new_batch(self):
        """Tabloda seçili satırın ihale bilgilerini alarak yeni parti ekleme dialogunu açar."""
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Seçim Gerekli",
                                "Lütfen önce tabloda bir ihale satırı seçin.")
            return
        ikn_item = self.table.item(row, 0)
        firma_item = self.table.item(row, 1)
        ihale_item = self.table.item(row, 2)
        if not ikn_item:
            QMessageBox.warning(self, "Hata", "Seçili satırdan bilgi alınamadı.")
            return
        ikn = ikn_item.text()
        firma = firma_item.text() if firma_item else ""
        ihale = ihale_item.text() if ihale_item else ""
        if NewBatchDialog(ikn, firma, ihale, self).exec():
            self.parent_window.refresh_all()

    def clear_filters(self):
        self.search.clear()
        self.cb_firm.setCurrentIndex(0)
        self.cb_tender.setCurrentIndex(0)
        self.cb_date_filter.setChecked(False)
    def open_edit(self, r):
        if EditDialog(r, self).exec(): self.parent_window.refresh_all()

    def delete_row(self, r):
        ikn = r[1]
        ihale = r[3]
        firma = r[2]
        
        msg = QMessageBox(self)
        msg.setWindowTitle("Silme Seçeneği")
        msg.setText("Bu kayıt için silme işlemini nasıl yapmak istersiniz?")
        msg.setInformativeText(f"IKN: {ikn}\nFirma: {firma}\nİhale: {ihale}")
        msg.setIcon(QMessageBox.Icon.Question)
        
        # Özel Butonlar
        btn_single = msg.addButton("Sadece Bu Partiyi Sil", QMessageBox.ButtonRole.AcceptRole)
        btn_all = msg.addButton("Tüm İhaleyi Sil (İş Bilgileri)", QMessageBox.ButtonRole.DestructiveRole)
        btn_cancel = msg.addButton("İptal", QMessageBox.ButtonRole.RejectRole)
        
        msg.exec()
        
        clicked_button = msg.clickedButton()
        
        if clicked_button == btn_single:
            try:
                delete_record(r[0])
                # Detailed Logging
                ikn = r[1]; firma = r[2]; ihale = r[3]; parti = r[4]
                log_action("Kayıt Silme", f"ID: {r[0]} | IKN: {ikn} | Firma: {firma} | Parti: {parti} | Ihale: {ihale}")
                QMessageBox.information(self, "Başarılı", "Seçili parti silindi.")
                self.parent_window.refresh_all()
            except Exception as e:
                QMessageBox.critical(self, "Hata", f"Silme işlemi başarısız: {e}")
                
        elif clicked_button == btn_all:
             # Onay iste (çünkü toplu silme)
            check = QMessageBox.question(self, "Onay", 
                                        f"BU İŞLEME AİT TÜM KAYITLAR SİLİNECEK!\n\nIKN: {ikn}\nFirma: {firma}\n\nEmin misiniz?",
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if check == QMessageBox.StandardButton.Yes:
                try:
                    count = delete_tender_group(ikn, firma)
                    log_action("Toplu Silme", f"IKN: {ikn}, Firma: {firma}, Silinen: {count}")
                    QMessageBox.information(self, "Başarılı", f"Toplam {count} adet kayıt silindi.")
                    self.parent_window.refresh_all()
                except Exception as e:
                    QMessageBox.critical(self, "Hata", f"Toplu silme işlemi başarısız: {e}")

            if self.parent_window: self.parent_window.refresh_all()

    def show_context_menu(self, pos):
        selected_items = self.table.selectedItems()
        if not selected_items:
            return
            
        menu = QtWidgets.QMenu(self)
        action_bulk_edit = menu.addAction("Seçili Kayıtları Topluca Düzenle")
        action_shift_dates = menu.addAction("Seçili Parti Son Teslim Tarihlerini Ötele")
        
        action = menu.exec(self.table.viewport().mapToGlobal(pos))
        
        if action == action_bulk_edit:
            selected_rows = set(item.row() for item in selected_items)
            records_to_edit = []
            for row in selected_rows:
                ikn_item = self.table.item(row, 0)
                if ikn_item:
                    rowid = ikn_item.data(Qt.ItemDataRole.UserRole)
                    if rowid:
                        for r in self.all_data:
                            if r[0] == rowid:
                                records_to_edit.append(r)
                                break
            
            if records_to_edit:
                if BulkEditDialog(records_to_edit, self).exec():
                    self.parent_window.refresh_all()
        elif action == action_shift_dates:
            selected_rows = set(item.row() for item in selected_items)
            records_to_edit = []
            for row in selected_rows:
                ikn_item = self.table.item(row, 0)
                if ikn_item:
                    rowid = ikn_item.data(Qt.ItemDataRole.UserRole)
                    if rowid:
                        for r in self.all_data:
                            if r[0] == rowid:
                                records_to_edit.append(r)
                                break
            
            if records_to_edit:
                if DateShiftDialog(records_to_edit, self).exec():
                    self.parent_window.refresh_all()

class DateShiftDialog(QDialog):
    def __init__(self, records, parent=None):
        super().__init__(parent)
        self.records = records
        self.setWindowTitle(f"Tarihleri Ötele ({len(records)} kayıt)")
        self.setFixedWidth(500)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        layout.addWidget(QLabel("<b>Ötelenecek Gün Sayısı:</b>"))
        layout.addWidget(QLabel("<small>(Pozitif: İleri, Negatif: Geri)</small>"))
        
        self.days_spin = QtWidgets.QSpinBox()
        self.days_spin.setRange(-3650, 3650)
        self.days_spin.setValue(0)
        self.days_spin.setSuffix(" gün")
        self.days_spin.setMinimumHeight(35)
        self.days_spin.valueChanged.connect(self.update_preview)
        layout.addWidget(self.days_spin)
        
        layout.addSpacing(10)
        layout.addWidget(QLabel("<b>Önizleme:</b>"))
        
        self.preview_table = QTableWidget()
        self.preview_table.setColumnCount(3)
        self.preview_table.setHorizontalHeaderLabels(["İhale/Parti", "Eski Tarih", "Yeni Tarih"])
        self.preview_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.preview_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.preview_table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        layout.addWidget(self.preview_table)
        
        self.update_preview()
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("Tarihleri Güncelle")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("İptal")
        buttons.accepted.connect(self.save_changes)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
    def update_preview(self):
        days = self.days_spin.value()
        self.preview_table.setRowCount(len(self.records))
        
        for i, r in enumerate(self.records):
            # r index: 0=rowid, 1=IKN, 2=Firma, 3=Ihale, 4=PartiNo, 5=Tarih
            name = f"{r[3]} (P: {r[4]})"
            old_date_str = str(r[5])[:10] if r[5] else ""
            
            self.preview_table.setItem(i, 0, QTableWidgetItem(name))
            self.preview_table.setItem(i, 1, QTableWidgetItem(format_date_tr(old_date_str)))
            
            if old_date_str:
                try:
                    old_date = datetime.strptime(old_date_str, "%Y-%m-%d")
                    new_date = old_date + timedelta(days=days)
                    new_date_str = new_date.strftime("%Y-%m-%d")
                    item = QTableWidgetItem(format_date_tr(new_date_str))
                    if days != 0:
                        item.setForeground(QBrush(QColor("#6366f1")))
                        font = item.font()
                        font.setBold(True)
                        item.setFont(font)
                    self.preview_table.setItem(i, 2, item)
                except:
                    self.preview_table.setItem(i, 2, QTableWidgetItem("-"))
            else:
                self.preview_table.setItem(i, 2, QTableWidgetItem("-"))

    def save_changes(self):
        days = self.days_spin.value()
        if days == 0:
            self.reject()
            return
            
        reply = QMessageBox.question(self, "Onay", f"{len(self.records)} kaydın tarihini {days} gün ötelemek istediğinize emin misiniz?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
            
        try:
            timestamp = datetime.now().strftime("%d.%m.%Y %H:%M")
            audit_log = f"Tarih Öteleme ({days} gün): {CURRENT_USER} ({timestamp})"
            
            log_details = []
            for r in self.records:
                rowid = r[0]
                old_date_str = str(r[5])[:10] if r[5] else ""
                if old_date_str:
                    old_date = datetime.strptime(old_date_str, "%Y-%m-%d")
                    new_date = old_date + timedelta(days=days)
                    new_date_str = new_date.strftime("%Y-%m-%d")
                    
                    update_record(rowid, "Parti Son Teslim Tarihi", new_date_str)
                    update_record(rowid, "SonGuncelleme", audit_log)
                    
                    # Log detayı ekle
                    log_details.append(f"IKN: {r[1]}, Firma: {r[2]}, Parti: {r[4]}")
            
            final_log = f"Gün: {days} | Detaylar: " + "; ".join(log_details)
            log_action("Toplu Tarih Öteleme", final_log)
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"İşlem sırasında hata oluştu: {e}")

# --- LOG KAYITLARI SEKME ---
class LogWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.all_logs = []  # Tüm log verileri burada tutulur
        self.setup_ui()
        self.refresh_logs()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Üst Panel (Başlık)
        top_layout = QHBoxLayout()
        title = QLabel("📜 Sistem İşlem Kayıtları")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #5e35b1;")
        top_layout.addWidget(title)
        top_layout.addStretch()
        btn_refresh = QPushButton("🔄 Yenile")
        btn_refresh.clicked.connect(self.refresh_logs)
        top_layout.addWidget(btn_refresh)
        layout.addLayout(top_layout)

        # Arama / Filtreleme Paneli
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("🔍 Ara:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("ID, tarih, kullanıcı, işlem veya detay...")
        self.search_edit.textChanged.connect(self.apply_log_filter)
        filter_layout.addWidget(self.search_edit, stretch=2)

        filter_layout.addSpacing(15)
        filter_layout.addWidget(QLabel("Kullanıcı:"))
        self.cb_user = QComboBox()
        self.cb_user.setView(QListView())
        self.cb_user.setItemDelegate(DropdownDelegate())
        self.cb_user.setMinimumWidth(130)
        self.cb_user.addItem("Tümü")
        self.cb_user.currentTextChanged.connect(self.apply_log_filter)
        filter_layout.addWidget(self.cb_user)

        filter_layout.addSpacing(15)
        filter_layout.addWidget(QLabel("İşlem Tipi:"))
        self.cb_action = QComboBox()
        self.cb_action.setView(QListView())
        self.cb_action.setItemDelegate(DropdownDelegate())
        self.cb_action.setMinimumWidth(160)
        self.cb_action.addItem("Tümü")
        self.cb_action.currentTextChanged.connect(self.apply_log_filter)
        filter_layout.addWidget(self.cb_action)

        btn_clr = QPushButton("Temizle")
        btn_clr.clicked.connect(self.clear_log_filters)
        filter_layout.addWidget(btn_clr)
        layout.addLayout(filter_layout)

        # Log Table
        self.table = QTableWidget()
        self.table.setAlternatingRowColors(True)
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["ID", "Tarih", "Kullanıcı", "İşlem", "Detaylar"])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSortingEnabled(True)

        header = self.table.horizontalHeader()
        self.table.setColumnWidth(0, 60)   # ID
        self.table.setColumnWidth(1, 140)  # Tarih
        self.table.setColumnWidth(2, 100)  # Kullanıcı
        self.table.setColumnWidth(3, 150)  # İşlem
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)  # Detaylar
        layout.addWidget(self.table)

    def refresh_logs(self):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 1000")
        self.all_logs = cursor.fetchall()
        conn.close()

        # Kullanıcı ve işlem tip combolarını güncelle
        users = sorted(set(log[2] for log in self.all_logs if log[2]))
        actions = sorted(set(log[3] for log in self.all_logs if log[3]))

        self.cb_user.blockSignals(True)
        current_user_sel = self.cb_user.currentText()
        self.cb_user.clear()
        self.cb_user.addItem("Tümü")
        self.cb_user.addItems(users)
        if current_user_sel in users:
            self.cb_user.setCurrentText(current_user_sel)
        self.cb_user.blockSignals(False)

        self.cb_action.blockSignals(True)
        current_action_sel = self.cb_action.currentText()
        self.cb_action.clear()
        self.cb_action.addItem("Tümü")
        self.cb_action.addItems(actions)
        if current_action_sel in actions:
            self.cb_action.setCurrentText(current_action_sel)
        self.cb_action.blockSignals(False)

        self.apply_log_filter()

    def apply_log_filter(self):
        txt = self.search_edit.text().lower()
        user_f = self.cb_user.currentText()
        action_f = self.cb_action.currentText()

        filtered = []
        for log in self.all_logs:
            if user_f != "Tümü" and str(log[2]) != user_f:
                continue
            if action_f != "Tümü" and str(log[3]) != action_f:
                continue
            if txt and txt not in str(log).lower():
                continue
            filtered.append(log)

        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(filtered))
        for i, log in enumerate(filtered):
            id_item = SortableTableWidgetItem(str(log[0]))
            id_item.setData(Qt.ItemDataRole.UserRole, log[0])
            id_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(i, 0, id_item)
            self.table.setItem(i, 1, QTableWidgetItem(str(log[1])))
            self.table.setItem(i, 2, QTableWidgetItem(str(log[2])))
            self.table.setItem(i, 3, QTableWidgetItem(str(log[3])))
            self.table.setItem(i, 4, QTableWidgetItem(str(log[4])))
        self.table.setSortingEnabled(True)

    def clear_log_filters(self):
        self.search_edit.clear()
        self.cb_user.setCurrentIndex(0)
        self.cb_action.setCurrentIndex(0)

# --- ABOUT DIALOG ---
class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Hakkında")
        self.setFixedSize(500, 350)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        
        # Info Text
        info_text = """
        <h3 style='color: #6366f1; margin-bottom:0;'>İhale Takip Uygulaması v6.56</h3>
        <br>
        <b>Geliştirici Bilgileri:</b></p>
        <ul>
        <li>Geliştirici: Mustafa Halil GÖRENTAŞ</li>
        <li>Kaynak Kod: <a href="https://github.com/mhalil/ihale_takip_sistemi">github.com/mhalil/ihale_takip_sistemi</a></li>
        </ul>
        <p><b>Teknik Bilgiler:</b></p>
        <ul>
            <li>Platform: Google Antigravity</li>
            <li>Metodoloji: Vibe Coding</li>
            <li>Programlama Dili: Python (3.12.4)</li>
            <li>Framework: PySide6 </li>
            <li>Veri Tabanı: SQLite</li>
        </ul>
       
        GPL Lisansı Altında Dağıtılmaktadır. | 2026
        """
        
        text_lbl = QLabel(info_text)
        text_lbl.setAlignment(Qt.AlignCenter)
        text_lbl.setOpenExternalLinks(True)
        layout.addWidget(text_lbl)
        
        layout.addStretch()
        
        btn_close = QPushButton("Kapat")
        btn_close.setFixedWidth(100)
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close, alignment=Qt.AlignCenter)

# --- ANA PENCERE ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("İhale Takip Sistemi")
        self.resize(1700, 900)
        self.showMaximized()
        
        # Kullanıcıya özel tema yükleme
        settings = QSettings("IhaleSystem", f"UserPrefs/{CURRENT_USER}")
        self.is_dark_mode = settings.value("dark_mode", "false") == "true"
        if self.is_dark_mode:
            app.setStyleSheet(DARK_STYLE)
        else:
            app.setStyleSheet(LIGHT_STYLE)
        
        central = QWidget(); self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        
        # Üst Bar (Tema Değiştirici)
        top_bar = QHBoxLayout()
        top_bar.addStretch()
        
        self.btn_user = QPushButton(f"👤 {CURRENT_USER}")
        self.btn_user.setObjectName("PrimaryBtn")
        self.btn_user.setFixedWidth(120)
        self.btn_user.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_user.clicked.connect(self.show_user_mgmt)
        top_bar.addWidget(self.btn_user)
        
        top_bar.addSpacing(5)
        
        self.btn_logout = QPushButton("🚪 Çıkış Yap")
        self.btn_logout.setFixedWidth(120)
        self.btn_logout.setCursor(Qt.CursorShape.PointingHandCursor)
        # Soft Red -> Vivid Red Hover
        self.btn_logout.setStyleSheet("""
            QPushButton {
                background-color: #ef5350; 
                color: white;
                border-radius: 6px;
                padding: 8px 8px;
                border: none;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        self.btn_logout.clicked.connect(self.logout)
        top_bar.addWidget(self.btn_logout)

        top_bar.addSpacing(10)
        
        self.btn_theme = QPushButton("☀️ Aydınlık Mod" if self.is_dark_mode else "🌙 Karanlık Mod")
        self.btn_theme.setObjectName("PrimaryBtn")
        self.btn_theme.setFixedWidth(140)
        self.btn_theme.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_theme.clicked.connect(self.toggle_theme)
        top_bar.addWidget(self.btn_theme)
        
        top_bar.addSpacing(5)
        
        self.btn_about = QPushButton("ℹ️ Hakkında")
        self.btn_about.setObjectName("PrimaryBtn")
        self.btn_about.clicked.connect(self.show_about)
        self.btn_about.setFixedWidth(110)
        self.btn_about.setCursor(Qt.CursorShape.PointingHandCursor)
        top_bar.addWidget(self.btn_about)
        
        layout.addLayout(top_bar)
        
        self.tabs = QTabWidget()
        self.summary_widget = SummaryWidget(self)
        self.detail_widget = DetailWidget(self)
        self.calendar_widget = CalendarWidget(self)
        self.tender_widget = TenderWidget(self)
        self.firm_widget = FirmSummaryWidget(self)
        self.log_widget = LogWidget() # Parent yok, tab'a eklenince reparent olacak
        
        self.tabs.addTab(self.summary_widget, "📊 Güncel İhale ve Parti Bilgileri")
        self.tabs.addTab(self.detail_widget, "📋 İhale ve Parti Bilgilerini Düzenle")
        self.tabs.addTab(self.calendar_widget, "📅 Takvim Görünümü")        
        self.tabs.addTab(self.tender_widget, "🏢 İhale Detayları")
        self.tabs.addTab(self.firm_widget, "🏭 Firma Özetleri")
        
        if CURRENT_USER_ROLE == "admin":
            self.tabs.addTab(self.log_widget, "📜 İşlem Kayıtları")
        
        layout.addWidget(self.tabs)
        
    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        if self.is_dark_mode:
            self.btn_theme.setText("☀️ Aydınlık Mod")
            app.setStyleSheet(DARK_STYLE)
        else:
            self.btn_theme.setText("🌙 Karanlık Mod")
            app.setStyleSheet(LIGHT_STYLE)
        # Kullanıcıya özel tema kaydı
        settings = QSettings("IhaleSystem", f"UserPrefs/{CURRENT_USER}")
        settings.setValue("dark_mode", self.is_dark_mode)
        # Widget'ları bilgilendir (bazı renkler manuel güncellenmeli)
        self.summary_widget.refresh_summary()
        self.calendar_widget.update_calendar_styles()
        self.calendar_widget.highlight_dates()
        self.detail_widget.apply_filters()
    
    def refresh_all(self):
        self.summary_widget.refresh_summary()
        self.calendar_widget.refresh_data()
        self.detail_widget.refresh_data()
        self.tender_widget.refresh_data()
        self.firm_widget.refresh_data()
        if CURRENT_USER_ROLE == "admin":
            self.log_widget.refresh_logs()
        
    def show_about(self):
        AboutDialog(self).exec()

    def show_user_mgmt(self):
        UserManagementDialog(self).exec()

    def logout(self):
        msg = QMessageBox(self)
        msg.setWindowTitle("Çıkış")
        msg.setText("Oturumu kapatmak istediğinize emin misiniz?")
        msg.setInformativeText("Otomatik giriş pasif edilecektir.")
        msg.setIcon(QMessageBox.Icon.Question)
        
        # Custom Buttons (Evet / Hayır)
        btn_yes = msg.addButton("Evet", QMessageBox.ButtonRole.YesRole)
        btn_no = msg.addButton("Hayır", QMessageBox.ButtonRole.NoRole)
        
        msg.exec()
        
        if msg.clickedButton() == btn_yes:
            settings = QSettings("IhaleSystem", "LoginSettings")
            settings.setValue("auto_login", "false")
            # Set flag for main loop
            self.logout_requested = True
            self.close()

if __name__ == "__main__":
    # Uygulama açılışında yedekleme kontrolü yap
    check_and_create_backup()
    
    app = QApplication(sys.argv)    
    app.setStyle('Fusion')
    
    # Global font
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    # Stylesheet application
    app.setStyleSheet(LIGHT_STYLE)
    
    while True:
        # Check for auto login
        settings = QSettings("IhaleSystem", "LoginSettings")
        auto_login = settings.value("auto_login", "false") == "true"
        
        login_success = False
        if auto_login:
            username = settings.value("username", "")
            password = settings.value("password", "")
            
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
            user_data = cursor.fetchone()
            if user_data:
                CURRENT_USER = username
                # Fetch role from DB (index 2) or default
                if len(user_data) > 2:
                    CURRENT_USER_ROLE = user_data[2]
                else:
                    CURRENT_USER_ROLE = "admin" if username == "admin" else "user"
                login_success = True
            conn.close()
        
        if not login_success:
            login = LoginDialog()
            if login.exec() == QDialog.DialogCode.Accepted:
                login_success = True
            else:
                break # User closed login dialog
                
        if login_success:
            w = MainWindow()
            w.logout_requested = False
            w.show()
            app.exec()
            
            if w.logout_requested:
                # Loop back to login
                # Force disable auto login in loop as we just logged out
                settings.setValue("auto_login", "false")
                continue
            else:
                break
        else:
            break
            
    sys.exit(0)
