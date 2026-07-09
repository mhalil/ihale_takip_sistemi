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
                                QFileDialog, QTextEdit, QCompleter, QStyleOptionViewItem
                                )
from PySide6.QtCore import Qt, QDate, QTimer, QRegularExpression, QSettings, QEvent
from PySide6.QtGui import QShortcut, QKeySequence
from PySide6.QtGui import (QIntValidator, QRegularExpressionValidator, QFont,
                            QColor,  QTextCharFormat, QBrush, QPainter, QStandardItem, QStandardItemModel)
from enum import IntEnum

# --- VERITABANI ALAN INDEKSLERI (Magic Number'lardan kurtul) ---
class Field(IntEnum):
    ID = 0
    IKN = 1
    FIRMA = 2
    IHALE_ADI = 3
    PARTI_NO = 4
    TESLIM_TARIHI = 5
    TUTAR = 6
    AMBAR_TESLIM = 7
    TEST_BASLADI = 8
    TEST_SONUC = 9
    KABUL_RAPOR = 10
    KABUL = 11
    ODEME = 13
    ACIKLAMA = 14
    MIKTAR = 16
    SOZLESME_TARIHI = 17
    MALZEME_DETAYI = 18
    HEYET_HABER = 19
    TEST_DETAY_B = 20
    TEST_DETAY_S = 21
    IHALE_TURU = 22
    IHALE_USULU = 23
    YAK_MALIYET = 24
    IHALE_TARIHI = 25
    ISE_BASLAMA = 26
    PARTI_TESLIM_SURESI = 27
    CARI_NO = 28
    PROJE_NO = 29
    KART_NO = 30
    TESLIM_AMBARI = 34

# --- OTURUM (Global degiskenlerden kurtul) ---
class SessionMeta(type):
    @property
    def user(cls):
        return cls._username
    @property
    def role(cls):
        return cls._role
    @property
    def is_admin(cls):
        return cls._role == "admin"
    @property
    def is_editor_or_admin(cls):
        return cls._role in ("admin", "editor")
    @property
    def can_delete(cls):
        return cls._role == "admin"
    @property
    def can_manage_users(cls):
        return cls._role == "admin"
    @property
    def can_view_logs(cls):
        return cls._role == "admin"

class Session(metaclass=SessionMeta):
    _username = "user"
    _role = "user"

    @classmethod
    def login(cls, username: str, role: str) -> None:
        cls._username = username
        cls._role = role

    @classmethod
    def logout(cls) -> None:
        cls._username = "user"
        cls._role = "user"

# --- VERITABANI MIGRATION (Yeni alanlari otomatik ekle) ---
MIGRATIONS = [
    ("ALTER TABLE data ADD COLUMN `Ihale Turu` TEXT DEFAULT ''", "Ihale Turu"),
    ("ALTER TABLE data ADD COLUMN `Ihale Usulu` TEXT DEFAULT ''", "Ihale Usulu"),
    ("ALTER TABLE data ADD COLUMN `Ihale Tarihi` TEXT DEFAULT ''", "Ihale Tarihi"),
    ("ALTER TABLE data ADD COLUMN `Ise Baslama Tarihi` TEXT DEFAULT ''", "Ise Baslama Tarihi"),
    ("ALTER TABLE data RENAME COLUMN `Isin Suresi` TO `Parti Teslim Suresi`", "Parti Teslim Suresi"),
    ("ALTER TABLE data ADD COLUMN `Parti Teslim Suresi` TEXT DEFAULT ''", "Parti Teslim Suresi"),
    ("ALTER TABLE data ADD COLUMN `Cari No` TEXT DEFAULT ''", "Cari No"),
    ("ALTER TABLE data ADD COLUMN `Proje No` TEXT DEFAULT ''", "Proje No"),
    ("ALTER TABLE data ADD COLUMN `Kart No` TEXT DEFAULT ''", "Kart No"),
    ("ALTER TABLE data ADD COLUMN `Test Detay B` TEXT DEFAULT ''", "Test Detay B"),
    ("ALTER TABLE data ADD COLUMN `Test Detay S` TEXT DEFAULT ''", "Test Detay S"),
    ("ALTER TABLE data ADD COLUMN `Teslim Ambari` TEXT DEFAULT ''", "Teslim Ambari"),
]

def run_migrations():
    conn = get_db_connection()
    cursor = conn.cursor()
    for sql, col_name in MIGRATIONS:
        try:
            cursor.execute(sql)
            conn.commit()
        except sqlite3.OperationalError:
            conn.rollback()
    conn.close()

# --- ORTAK SAYI FORMATLAMA FONKSIYONU (format_on_type tekrari icin) ---
def format_number_edit(edit_widget: QLineEdit, text: str) -> None:
    if not text:
        return
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
    if not integer_part and not decimal_part:
        return
    try:
        if integer_part.lstrip('-').isdigit():
            is_negative = integer_part.startswith('-')
            val = integer_part.lstrip('-')
            rev_val = val[::-1]
            groups = [rev_val[i:i+3] for i in range(0, len(rev_val), 3)]
            formatted_int = ".".join(groups)[::-1]
            if is_negative:
                formatted_int = "-" + formatted_int
            new_text = formatted_int + decimal_part
            edit_widget.blockSignals(True)
            edit_widget.setText(new_text)
            edit_widget.blockSignals(False)
            new_len = len(new_text)
            new_pos = cursor_pos + (new_len - old_len)
            edit_widget.setCursorPosition(max(0, new_pos))
    except:
        pass

def _is_checked(value):
    try:
        return value is not None and float(value) == 1.0
    except (ValueError, TypeError):
        return False

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

class WordWrapDelegate(QStyledItemDelegate):
    def __init__(self, wrap_columns, parent=None):
        super().__init__(parent)
        if isinstance(wrap_columns, int):
            self.wrap_columns = [wrap_columns]
        else:
            self.wrap_columns = wrap_columns

    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        if index.column() in self.wrap_columns:
            option.features |= QStyleOptionViewItem.ViewItemFeature.WrapText
            option.textElideMode = Qt.TextElideMode.ElideNone
        else:
            option.displayAlignment |= Qt.AlignmentFlag.AlignVCenter
            option.features &= ~QStyleOptionViewItem.ViewItemFeature.WrapText

    def paint(self, painter, option, index):
        if index.column() in self.wrap_columns:
            option.features |= QStyleOptionViewItem.ViewItemFeature.WrapText
        super().paint(painter, option, index)

COMMON_STYLE = """
QTabWidget::pane { border: none; }
QTabWidget > QWidget { background: transparent; }
QTabBar::tab { padding: 10px 20px; border-top-left-radius: 8px; border-top-right-radius: 8px; margin-right: 2px; font-weight: bold; }
QPushButton { border-radius: 6px; padding: 8px 16px; font-weight: bold; border: none; }
QLineEdit, QComboBox, QDateEdit { border-radius: 6px; padding: 8px; }
QTableWidget { border-radius: 8px; }
QHeaderView::section { padding: 10px; border: none; font-weight: bold; }
QScrollBar:vertical { border: none; width: 10px; margin: 0px; }
QScrollBar::handle:vertical { min-height: 20px; border-radius: 5px; }
"""

LIGHT_STYLE = COMMON_STYLE + """
QMainWindow, QDialog { background-color: #f1f5f9; }
QToolTip { background-color: #1e293b; color: #f8fafc; border: 1px solid #334155; }
QTabBar::tab { background: #cbd5e1; color: #475569; }
QTabBar::tab:selected { background: #6366f1; color: white; }
QPushButton { background-color: #6366f1; color: white; }
QPushButton:hover { background-color: #4f46e5; }
QPushButton#SecondaryBtn { background-color: #94A3B8#94A3B8#94A3B8#94A3B8#94A3B8; }
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
QTableWidget, QListWidget { background-color: white; border: 1px solid #cbd5e1; gridline-color: #e2e8f0; color: #1e293b; alternate-background-color: #eff6ff; }
QHeaderView::section { background-color: #e2e8f0; color: #475569; }
QScrollBar:vertical { background: #e2e8f0; }
QScrollBar::handle:vertical { background: #94a3b8; }
QScrollArea, QScrollArea QWidget, QTabWidget::pane { background-color: #f1f5f9; border: none; }
QMenu { background-color: white; color: #1e293b; border: 1px solid #cbd5e1; }
QMenu::item:selected { background-color: #6366f1; color: white; }
QCalendarWidget QToolButton { padding: 4px 14px; min-width: 70px; }
QCalendarWidget QSpinBox { width: 80px; padding: 2px; }
QCalendarWidget QWidget#qt_calendar_navigationbar { min-height: 40px; }
"""

def get_labs():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM labs")
        labs = [r[0] for r in cursor.fetchall()]
        conn.close()

        # Türkçe Alfabetik Sıralama (ç, ğ, ı, ö, ş, ü dikkate alınarak)
        tr_alphabet = "AaBbCcÇçDdEeFfGgĞğHhIıİiJjKkLlMmNnOoÖöPpRrSsŞşTtUuÜüVvYyZz"
        tr_key_map = {c: i for i, c in enumerate(tr_alphabet)}
        def tr_sort(s):
            return [tr_key_map.get(c, ord(c)) for c in s]

        return sorted(labs, key=tr_sort)
    except:
        return ["TSE", "İSTON", "Royaltest", "Teknolab"]

def get_ihale_turu_list():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM ihale_turu_list")
        items = [r[0] for r in cursor.fetchall()]
        conn.close()
        tr_alphabet = "AaBbCcÇçDdEeFfGgĞğHhIıİiJjKkLlMmNnOoÖöPpRrSsŞşTtUuÜüVvYyZz"
        tr_key_map = {c: i for i, c in enumerate(tr_alphabet)}
        return sorted(items, key=lambda s: [tr_key_map.get(c, ord(c)) for c in s])
    except:
        return []

def get_ihale_usulu_list():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM ihale_usulu_list")
        items = [r[0] for r in cursor.fetchall()]
        conn.close()
        tr_alphabet = "AaBbCcÇçDdEeFfGgĞğHhIıİiJjKkLlMmNnOoÖöPpRrSsŞşTtUuÜüVvYyZz"
        tr_key_map = {c: i for i, c in enumerate(tr_alphabet)}
        return sorted(items, key=lambda s: [tr_key_map.get(c, ord(c)) for c in s])
    except:
        return []

class MultiSelectComboBox(QComboBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setEditable(True)
        self.lineEdit().setReadOnly(True)
        self.lineEdit().setPlaceholderText("Laboratuvar seçin...")
        self.closeOnSelect = False

        # Standart model yerine checkable itemları destekleyen model
        self.model().itemChanged.connect(self.update_text)
        self.view().viewport().installEventFilter(self)

    def eventFilter(self, obj, event):
        if obj == self.view().viewport() and event.type() == QEvent.Type.MouseButtonRelease:
            index = self.view().indexAt(event.position().toPoint())
            item = self.model().itemFromIndex(index)
            if item:
                if item.text() == "+ Yeni Laboratuvar Ekle...":
                    self.add_custom_lab_dialog()
                else:
                    item.setCheckState(Qt.CheckState.Unchecked if item.checkState() == Qt.CheckState.Checked else Qt.CheckState.Checked)
            return True
        return super().eventFilter(obj, event)


    def add_custom_lab_dialog(self):
        new_lab, ok = QtWidgets.QInputDialog.getText(self, "Laboratuvar Ekle", "Yeni Laboratuvar Adı:", QLineEdit.EchoMode.Normal)
        if ok and new_lab.strip():
            lab_name = new_lab.strip()[:50] # 50 karakter sınırı

            # Veri tabanına kalıcı olarak ekle (Ayarlar'da da görünsün)
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("INSERT OR IGNORE INTO labs (name) VALUES (?)", (lab_name,))
                conn.commit()
                conn.close()
            except: pass

            # Zaten varsa sadece işaretle
            for i in range(self.model().rowCount()):
                if self.model().item(i).text() == lab_name:
                    self.model().item(i).setCheckState(Qt.CheckState.Checked)
                    return

            # Yeni item ekle (Ekle butonunun bir üstüne)
            item = QStandardItem(lab_name)
            item.setCheckable(True)
            item.setCheckState(Qt.CheckState.Checked)
            self.model().insertRow(self.model().rowCount() - 1, item)
            self.update_text()

    def add_labs(self, labs, current_val=""):
        self.model().blockSignals(True)
        self.model().clear()
        current_list = [x.strip() for x in current_val.split(",")] if current_val else []

        # Ana liste
        for lab in labs:
            item = QStandardItem(lab)
            item.setCheckable(True)
            if lab in current_list:
                item.setCheckState(Qt.CheckState.Checked)
            else:
                item.setCheckState(Qt.CheckState.Unchecked)
            self.model().appendRow(item)

        # Listede olmayan ama veride olan "özel" girişleri ekle
        for val in current_list:
            if val and val not in labs:
                item = QStandardItem(val)
                item.setCheckable(True)
                item.setCheckState(Qt.CheckState.Checked)
                self.model().appendRow(item)

        # En sona ekleme butonu
        add_item = QStandardItem("+ Yeni Laboratuvar Ekle...")
        add_item.setCheckable(False)
        add_item.setForeground(QColor("#6366f1")) # Indigo rengi
        font = QFont()
        font.setBold(True)
        add_item.setFont(font)
        self.model().appendRow(add_item)

        self.model().blockSignals(False)
        self.update_text()

    def update_text(self):
        try:
            line_edit = self.lineEdit()
        except RuntimeError:
            return
        checked_items = []
        for i in range(self.model().rowCount()):
            item = self.model().item(i)
            if item and item.checkState() == Qt.CheckState.Checked:
                checked_items.append(item.text())

        res = ", ".join(checked_items)
        try:
            line_edit.setText(res)
            self.setToolTip(res)
        except RuntimeError:
            pass

    def get_checked_items(self):
        items = []
        for i in range(self.model().rowCount()):
            item = self.model().item(i)
            if item and item.checkState() == Qt.CheckState.Checked:
                items.append(item.text())
        return ", ".join(items)

# --- GLOBAL CONFIG ---
COLUMN_MAPPING = {
    "Ambar Teslimi Gerçekleşti": "Ambar teslimi gerceklesti",
    "Testler Başladı": "Testler basladi",
    "Test Sonuçları Geldi": "Test sonuclari geldi",
    "Kabul Raporu imzada": "Muayene - Kabul  Evragi imzada",
    "Kabul Yapıldı": "Kabul Yapildi",
    "Heyet Başkanına Haber Verildi": "Heyet Baskanina Haber Verildi",
    "Ödeme Belgesi Oluşturuldu": "Odeme Emri Hazirlandi",
    "1. Ambar Teslimi Gerçekleşti": "Ambar teslimi gerceklesti",
    "2. Heyet Başkanına Haber Verildi": "Heyet Baskanina Haber Verildi",
    "3. Testler Başladı": "Testler basladi",
    "4. Test Sonuçları Geldi": "Test sonuclari geldi",
    "5. Kabul Raporu imzada": "Muayene - Kabul  Evragi imzada",
    "6. Kabul Yapıldı": "Kabul Yapildi",
    "7. Ödeme Belgesi Oluşturuldu": "Odeme Emri Hazirlandi"
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
            role = user[2] if len(user) > 2 else ("admin" if username == "admin" else "user")
            Session.login(username, role)

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

        pw_layout.addWidget(QLabel(f"<b>Kullanıcı:</b> {Session.user}"))

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
        if Session.can_manage_users:
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

            self.role_combo = QtWidgets.QComboBox()
            self.role_combo.addItems(["user", "editor", "admin"])
            add_layout.addWidget(QLabel("Rol:"))
            add_layout.addWidget(self.role_combo)

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

            self.role_edit_combo = QtWidgets.QComboBox()
            self.role_edit_combo.addItems(["user", "editor", "admin"])
            role_layout.addWidget(QLabel("Rol:"))
            role_layout.addWidget(self.role_edit_combo)

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

        update_password(Session.user, pw1)
        log_action("Şifre Değiştirme", f"Kullanıcı: {Session.user}")
        QMessageBox.information(self, "Başarılı", "Şifreniz güncellendi.")
        self.new_pw.clear()
        self.confirm_pw.clear()

    def handle_add_user(self):
        name = self.new_username.text()
        pw = self.new_user_pw.text()
        pw_confirm = self.new_user_pw_confirm.text()
        role = self.role_combo.currentText()

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
            self.role_combo.setCurrentIndex(0)
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
        editors = sorted([u for u, r in users_raw if r == "editor"])
        users = sorted([u for u, r in users_raw if r not in ("admin", "editor")])

        html = ""
        if admins:
            html += "<b>👑 Yöneticiler (Admin):</b><br>" + ", ".join(admins) + "<br><br>"
        if editors:
            html += "<b>✏️ Editörler (Editor):</b><br>" + ", ".join(editors) + "<br><br>"
        if users:
            html += "<b>👁️ Kullanıcılar (User):</b><br>" + ", ".join(users)

        self.user_list.setText(html)

    def on_role_user_selected(self):
        data = self.role_user_combo.currentData()
        if data:
            username, role = data
            idx = self.role_edit_combo.findText(role)
            if idx >= 0:
                self.role_edit_combo.setCurrentIndex(idx)
            self.role_edit_combo.setEnabled(username != "admin")

    def handle_role_update(self):
        data = self.role_user_combo.currentData()
        if not data: return

        username, old_role = data
        new_role = self.role_edit_combo.currentText()

        if username == "admin" and new_role != "admin":
             QMessageBox.warning(self, "Hata", "Ana 'admin' kullanıcısının yetkisi alınamaz!")
             self.role_edit_combo.setCurrentText("admin")
             return

        update_user_role(username, new_role)
        log_action("Yetki Güncelleme", f"Kullanıcı: {username}, Yeni Rol: {new_role}")
        QMessageBox.information(self, "Başarılı", f"'{username}' için yetki güncellendi.")

        # Refresh lists
        self.update_user_list_display()
        self.refresh_role_combo()

# --- FİRMA DETAY DİALOG ---
class FirmDetailDialog(QDialog):
    def __init__(self, firm_name, tenders, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Firma Detayları: {firm_name}")
        self.resize(1300, 650)
        self.firm_name = firm_name
        self.tenders = tenders

        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        title = QLabel(f"🏢 {firm_name} - İhale Geçmişi")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #6366f1;")
        layout.addWidget(title)

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "IKN No", "İhale Adı", "Sözleşme Tutarı",
            "İhale Tarihi", "Sözleşme Tarihi", "İşe Başlama Tarihi", "İş Sonu Tarihi"
        ])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.setWordWrap(True)
        self.table.setItemDelegate(WordWrapDelegate(1, self.table))
        self.table.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollMode.ScrollPerPixel)

        self.table.setRowCount(len(tenders))
        for i, t in enumerate(tenders):
            parts = t["parts"]
            # En son güncellenen veriden tarihleri al
            ihale_tarihi_raw = str(parts[0][25])[:10] if len(parts[0]) > 25 and parts[0][25] else ""
            sozlesme_raw = parts[0][17] if len(parts[0]) > 17 else ""
            ise_baslama_raw = str(parts[0][26])[:10] if len(parts[0]) > 26 and parts[0][26] else ""

            delivery_dates = [p[5] for p in parts if p[5]]
            is_sonu_raw = max(delivery_dates) if delivery_dates else ""

            # IKN
            self.table.setItem(i, 0, SortableTableWidgetItem(str(t["ikn"])))

            # İhale Adı
            self.table.setItem(i, 1, SortableTableWidgetItem(str(t["ihale"])))

            # Sözleşme Tutarı
            tutar_val = t.get("total_amount", 0.0)
            tutar_item = SortableTableWidgetItem(display_money(tutar_val))
            tutar_item.setData(Qt.ItemDataRole.UserRole, tutar_val)
            tutar_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.table.setItem(i, 2, tutar_item)

            # İhale Tarihi
            ihale_item = SortableTableWidgetItem(format_date_tr(ihale_tarihi_raw))
            ihale_item.setData(Qt.ItemDataRole.UserRole, ihale_tarihi_raw if ihale_tarihi_raw else "0000-00-00")
            ihale_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(i, 3, ihale_item)

            # Sözleşme Tarihi
            s_item = SortableTableWidgetItem(format_date_tr(sozlesme_raw))
            s_item.setData(Qt.ItemDataRole.UserRole, sozlesme_raw if sozlesme_raw else "0000-00-00")
            s_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(i, 4, s_item)

            # İşe Başlama
            b_item = SortableTableWidgetItem(format_date_tr(ise_baslama_raw))
            b_item.setData(Qt.ItemDataRole.UserRole, ise_baslama_raw if ise_baslama_raw else "0000-00-00")
            b_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(i, 5, b_item)

            # İş Sonu
            e_item = SortableTableWidgetItem(format_date_tr(is_sonu_raw))
            e_item.setData(Qt.ItemDataRole.UserRole, is_sonu_raw if is_sonu_raw else "0000-00-00")
            e_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(i, 6, e_item)

        # Boyutlandırma Ayarları
        self.table.resizeColumnsToContents()
        self.table.resizeRowsToContents()
        # Satır yüksekliklerini maksimum 2 satır (60px) olacak şekilde sınırla
        for i in range(self.table.rowCount()):
            if self.table.rowHeight(i) > 60:
                self.table.setRowHeight(i, 60)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        # İhale Adı sütununu esnek yap ama diğerleri içeriğe göre kalsın
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

        layout.addWidget(self.table)

        # Toplam Tutar
        total_amount = sum(t.get("total_amount", 0.0) for t in self.tenders)
        total_layout = QHBoxLayout()
        total_layout.addStretch()
        total_label = QLabel(f"<b>Toplam Sözleşme Tutarı: {display_money(total_amount)}</b>")
        lbl_bg = "#f1f5f9"
        total_label.setStyleSheet(f"font-size: 14px; color: #6366f1; background-color: {lbl_bg}; padding: 5px 12px; border-radius: 6px; border: 1px solid #6366f1;")
        total_layout.addWidget(total_label)
        layout.addLayout(total_layout)

        btn_box = QHBoxLayout()
        self.btn_export = QPushButton("📊 CSV Olarak Dışa Aktar")
        self.btn_export.setObjectName("InfoBtn")
        self.btn_export.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_export.clicked.connect(self.export_to_csv)
        btn_box.addWidget(self.btn_export)
        btn_box.addStretch()
        close_btn = QPushButton("Kapat")
        close_btn.setFixedWidth(100)
        close_btn.clicked.connect(self.accept)
        btn_box.addWidget(close_btn)
        layout.addLayout(btn_box)

    def export_to_csv(self):
        default_name = f"{self.firm_name}_ihale_gecmisi.csv"
        path, _ = QFileDialog.getSaveFileName(self, "Verileri CSV Olarak Kaydet", default_name, "CSV Dosyası (*.csv)")
        if not path:
            return
        try:
            headers = [self.table.horizontalHeaderItem(i).text() for i in range(self.table.columnCount())]
            with open(path, mode='w', encoding='utf-8-sig', newline='') as file:
                writer = csv.writer(file, delimiter=';')
                writer.writerow([f"Firma: {self.firm_name}"])
                writer.writerow(headers)
                for row in range(self.table.rowCount()):
                    row_data = [self.table.item(row, col).text() if self.table.item(row, col) else ""
                                for col in range(self.table.columnCount())]
                    writer.writerow(row_data)
            QMessageBox.information(self, "Başarılı", f"Veriler başarıyla dışa aktarıldı:\n{path}")
            log_action("CSV Dışa Aktar (Firma Detayları)", f"Dosya: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"CSV dışa aktarma hatası:\n{e}")

# --- CUSTOM WIDGETS ---
class SortableTableWidgetItem(QTableWidgetItem):
    def __lt__(self, other):
        # Özel sıralama anahtarı (UserRole) varsa ona göre sırala
        v1 = self.data(Qt.ItemDataRole.UserRole)
        v2 = other.data(Qt.ItemDataRole.UserRole)

        if v1 is not None and v2 is not None:
            try:
                return v1 < v2
            except (TypeError, ValueError):
                pass # Farklı tipler gelirse metin sıralamasına düş

        # Standart metin sıralaması (Özyinelemeyi önlemek için super().__lt__ kullanmıyoruz)
        # Türkçe karakter desteği ile sırala
        return tr_key(self.text()) < tr_key(other.text())


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

        if not os.path.exists(db_path): return
        os.makedirs(backup_dir, exist_ok=True)

        backups = [f for f in os.listdir(backup_dir) if f.startswith('veriler_yedek_') and f.endswith('.db')]
        needs_backup = False

        if not backups:
            needs_backup = True
        else:
            latest_time = None
            for backup in backups:
                try:
                    time_str = backup.replace("veriler_yedek_", "").replace(".db", "")
                    backup_dt = datetime.strptime(time_str, "%Y-%m-%d_%H-%M-%S")
                    if latest_time is None or backup_dt > latest_time:
                        latest_time = backup_dt
                except ValueError:
                    backup_path = os.path.join(backup_dir, backup)
                    mtime_dt = datetime.fromtimestamp(os.path.getmtime(backup_path))
                    if latest_time is None or mtime_dt > latest_time:
                        latest_time = mtime_dt

            if latest_time and (datetime.now() - latest_time) >= timedelta(days=7):
                needs_backup = True

        if needs_backup:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            backup_file = os.path.join(backup_dir, f"veriler_yedek_{timestamp}.db")
            shutil.copy(db_path, backup_file)
            print(f"Otomatik haftalık yedek alındı: {backup_file}")

            # Son 5 yedeği tut, eskileri temizle
            backups = sorted([os.path.join(backup_dir, f) for f in os.listdir(backup_dir) if f.startswith('veriler_yedek_')])
            while len(backups) > 5:
                old_backup = backups.pop(0)
                try: os.remove(old_backup)
                except: pass
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

    # --- DB INIT & MIGRATIONS ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS data (
            "IKN" TEXT,
            "Yuklenici Firma" TEXT,
            "Ihale Adi" TEXT,
            "Parti No" TEXT,
            "Parti Son Teslim Tarihi" TEXT,
            "Parti Tutari" REAL,
            "Ambar teslimi gerceklesti" REAL DEFAULT 0.0,
            "Testler basladi" REAL DEFAULT 0.0,
            "Test sonuclari geldi" REAL DEFAULT 0.0,
            "Muayene - Kabul  Evragi imzada" REAL DEFAULT 0.0,
            "Kabul Yapildi" REAL DEFAULT 0.0,
            "Odeme Emri Hazirlandi" REAL DEFAULT 0.0,
            "Aciklama" TEXT,
            "SonGuncelleme" TEXT,
            "Parti Miktari" TEXT,
            "Sozlesme Tarihi" TEXT,
            "Malzeme Detayi" TEXT,
            "Heyet Baskanina Haber Verildi" REAL DEFAULT 0.0,
            "Testler Basladi Detay" TEXT,
            "Test Sonuclari Geldi Detay" TEXT,
            "Ihale Turu" TEXT,
            "Ihale Usulu" TEXT,
            "Yak. Maliyet" REAL,
            "Ihale Tarihi" TEXT,
            "Ise Baslama Tarihi" TEXT,
            "Parti Teslim Suresi" TEXT,
            "Cari No" TEXT,
            "Proje No" TEXT,
            "Kart No" TEXT,
            "Teslim Ambari" TEXT
        )
    ''')
    try:
        cursor.execute("SELECT `Parti Miktari` FROM data LIMIT 1")
    except:
        try:
            cursor.execute("ALTER TABLE data ADD COLUMN `Parti Miktari` TEXT")
            conn.commit()
        except: pass

    try:
        cursor.execute("SELECT `Sozlesme Tarihi` FROM data LIMIT 1")
    except:
        try:
            cursor.execute("ALTER TABLE data ADD COLUMN `Sozlesme Tarihi` TEXT")
            conn.commit()
        except: pass

    try:
        cursor.execute("SELECT `Heyet Baskanina Haber Verildi` FROM data LIMIT 1")
    except:
        try:
            cursor.execute("ALTER TABLE data ADD COLUMN `Heyet Baskanina Haber Verildi` REAL DEFAULT 0.0")
            conn.commit()
        except: pass

    for col in ["Testler Basladi Detay", "Test Sonuclari Geldi Detay", "Ise Baslama Tarihi", "Teslim Ambari"]:
        try:
            cursor.execute(f"SELECT `{col}` FROM data LIMIT 1")
        except:
            try:
                cursor.execute(f"ALTER TABLE data ADD COLUMN `{col}` TEXT")
                conn.commit()
            except: pass

    cursor.execute("CREATE TABLE IF NOT EXISTS labs (id INTEGER PRIMARY KEY, name TEXT UNIQUE)")
    cursor.execute("SELECT count(*) FROM labs")
    if cursor.fetchone()[0] == 0:
        for lab in ["TSE", "İSTON", "Royaltest", "Teknolab"]:
            cursor.execute("INSERT OR IGNORE INTO labs (name) VALUES (?)", (lab,))
        conn.commit()

    cursor.execute("CREATE TABLE IF NOT EXISTS ihale_turu_list (id INTEGER PRIMARY KEY, name TEXT UNIQUE)")
    cursor.execute("SELECT count(*) FROM ihale_turu_list")
    if cursor.fetchone()[0] == 0:
        try:
            cursor.execute("SELECT DISTINCT `Ihale Turu` FROM data WHERE `Ihale Turu` IS NOT NULL AND `Ihale Turu` != ''")
            existing = [r[0] for r in cursor.fetchall()]
            if existing:
                for val in existing:
                    cursor.execute("INSERT OR IGNORE INTO ihale_turu_list (name) VALUES (?)", (val,))
            else:
                for val in ["Mal", "Hizmet", "Yapım", "Danışmanlık"]:
                    cursor.execute("INSERT OR IGNORE INTO ihale_turu_list (name) VALUES (?)", (val,))
        except:
            for val in ["Mal", "Hizmet", "Yapım", "Danışmanlık"]:
                cursor.execute("INSERT OR IGNORE INTO ihale_turu_list (name) VALUES (?)", (val,))
        conn.commit()

    cursor.execute("CREATE TABLE IF NOT EXISTS ihale_usulu_list (id INTEGER PRIMARY KEY, name TEXT UNIQUE)")
    cursor.execute("SELECT count(*) FROM ihale_usulu_list")
    if cursor.fetchone()[0] == 0:
        try:
            cursor.execute("SELECT DISTINCT `Ihale Usulu` FROM data WHERE `Ihale Usulu` IS NOT NULL AND `Ihale Usulu` != ''")
            existing = [r[0] for r in cursor.fetchall()]
            if existing:
                for val in existing:
                    cursor.execute("INSERT OR IGNORE INTO ihale_usulu_list (name) VALUES (?)", (val,))
            else:
                for val in ["Açık İhale", "Belli İstekli", "Pazarlık", "Doğrudan Temin"]:
                    cursor.execute("INSERT OR IGNORE INTO ihale_usulu_list (name) VALUES (?)", (val,))
        except:
            for val in ["Açık İhale", "Belli İstekli", "Pazarlık", "Doğrudan Temin"]:
                cursor.execute("INSERT OR IGNORE INTO ihale_usulu_list (name) VALUES (?)", (val,))
        conn.commit()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("admin", "admin", "admin"))

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            user TEXT,
            action TEXT,
            details TEXT
        )
    ''')
    cursor.execute("CREATE TABLE IF NOT EXISTS ambarlar (id INTEGER PRIMARY KEY, name TEXT UNIQUE)")
    cursor.execute("SELECT count(*) FROM ambarlar")
    if cursor.fetchone()[0] == 0:
        for amb in ["Merkez Ambar", "Şantiye Ambarı", "Lojistik Ambar"]:
            cursor.execute("INSERT OR IGNORE INTO ambarlar (name) VALUES (?)", (amb,))
        conn.commit()

    conn.commit()
    return conn

def get_ambar_list():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM ambarlar ORDER BY name")
        result = [r[0] for r in cursor.fetchall()]
        conn.close()
        return result
    except Exception as e:
        print(f"Ambar listesi hatası: {e}")
        return []

def log_action(action, details=""):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO logs (timestamp, user, action, details) VALUES (?, ?, ?, ?)",
                       (timestamp, Session.user, action, details))
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

# Global session, Session.login() ile yonetilir

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

def display_money(value):
    return format_money(value) + " TL"

def format_number(value):
    if value is None or str(value).strip() == "":
        return "-"
    try:
        val = parse_money(value)
        if val.is_integer():
            formatted = f"{int(val):,}"
        else:
            formatted = f"{val:,.2f}"
            if formatted.endswith(".00"):
                formatted = formatted[:-3]
        return formatted.replace(',', 'X').replace('.', ',').replace('X', '.')
    except:
        return str(value)

def parse_money(text):
    if text is None:
        return 0.0
    if isinstance(text, (int, float)):
        return float(text)
    try:
        # Eğer string ise: Noktaları sil (binlik), virgülü noktaya çevir (ondalık)
        text_str = str(text).replace("TL", "").strip()
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

def format_currency_input(line_edit, text):
    if not text:
        return

    cursor = line_edit.cursorPosition()
    text_before_cursor = text[:cursor]
    digit_count_before = len(text_before_cursor.replace('.', ''))

    line_edit.blockSignals(True)

    clean_text = text.replace('.', '')

    if ',' in clean_text:
        parts = clean_text.split(',', 1)
        integer_part = parts[0]
        decimal_part = parts[1][:2]
        has_comma = True
    else:
        integer_part = clean_text
        decimal_part = ""
        has_comma = False

    if integer_part.isdigit():
        formatted_int = "{:,}".format(int(integer_part)).replace(',', '.')
        new_text = formatted_int
        if has_comma:
            new_text += "," + decimal_part
    else:
        new_text = clean_text

    line_edit.setText(new_text)

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
    cursor.execute("SELECT rowid, * FROM data")
    rows = cursor.fetchall()
    conn.close()
    return rows

def update_record(rowid, field_name, value, cursor=None):
    clean_field = "".join([c for c in field_name if c.isalnum() or c in " _-."])
    try:
        if cursor:
            cursor.execute(f"UPDATE data SET `{clean_field}` = ? WHERE rowid = ?", (value, rowid))
        else:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute(f"UPDATE data SET `{clean_field}` = ? WHERE rowid = ?", (value, rowid))
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"Veri güncellenirken hata oluştu ({clean_field}): {e}")


def recalculate_parti_teslim_suresi():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT rowid, `Ise Baslama Tarihi`, `Parti Son Teslim Tarihi`
        FROM data
        WHERE `Ise Baslama Tarihi` IS NOT NULL AND `Ise Baslama Tarihi` != ''
          AND `Parti Son Teslim Tarihi` IS NOT NULL AND `Parti Son Teslim Tarihi` != ''
    """)
    rows = cursor.fetchall()
    for rowid, baslama, teslim in rows:
        try:
            d1 = datetime.strptime(str(baslama)[:10], "%Y-%m-%d")
            d2 = datetime.strptime(str(teslim)[:10], "%Y-%m-%d")
            diff = (d2 - d1).days + 1
            cursor.execute("UPDATE data SET `Parti Teslim Suresi` = ? WHERE rowid = ?", (f"{diff} Gün", rowid))
        except:
            pass
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
        SELECT rowid, * FROM data
        WHERE (`Odeme Emri Hazirlandi` IS NULL OR `Odeme Emri Hazirlandi` IN (0, 0.0, '0', '0.0', ''))
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
        self.setup_ui()
        self.resize(self.width(), int(self.sizeHint().height() * 1.35))

    def setup_ui(self):
        self.setFixedWidth(725)
        main_layout = QVBoxLayout(self)
        self.fields = {}

        self.setStyleSheet("""
            QLineEdit, QTextEdit, QDateEdit, QComboBox {
                background-color: white;
                color: #1e293b;
                border: 1px solid #94a3b8;
                border-radius: 6px;
                padding: 6px;
            }
            QComboBox::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: right center;
                width: 28px;
                background-color: #e2e8f0;
                border-top-right-radius: 6px;
                border-bottom-right-radius: 6px;
            }
            QComboBox::drop-down:hover {
                background-color: #cbd5e1;
            }
            QDateEdit::drop-down {
                subcontrol-origin: padding;
                subcontrol-position: right center;
                width: 28px;
                background-color: #e2e8f0;
                border-top-right-radius: 6px;
                border-bottom-right-radius: 6px;
            }
            QDateEdit::drop-down:hover {
                background-color: #cbd5e1;
            }
            QDateEdit::drop-down:pressed {
                background-color: #94a3b8;
            }
            QCalendarWidget QWidget {
                background-color: white;
                color: #1e293b;
            }
            QCalendarWidget QToolButton {
                color: #1e293b;
                background-color: #e2e8f0;
                padding: 4px 12px;
                min-width: 70px;
            }
            QCalendarWidget QToolButton:hover {
                background-color: #cbd5e1;
            }
            QCalendarWidget QSpinBox {
                width: 70px;
                padding: 2px 6px;
            }
            QCalendarWidget QTableView {
                color: #1e293b;
                selection-background-color: #6366f1;
                selection-color: white;
            }
            QCalendarWidget QAbstractItemView:disabled {
                color: #94a3b8;
            }
        """)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # 1. SEKME: TEMEL BİLGİLER
        tab_basic = QWidget()
        layout_basic = QVBoxLayout(tab_basic)
        scroll_basic = QScrollArea()
        scroll_basic.setWidgetResizable(True)
        scroll_basic_content = QWidget()
        scroll_basic_layout = QVBoxLayout(scroll_basic_content)

        # IKN
        scroll_basic_layout.addWidget(QLabel("<b>IKN:</b>"))
        self.fields["IKN"] = QLineEdit()
        self.fields["IKN"].setPlaceholderText("Örn: 2026/12345")
        scroll_basic_layout.addWidget(self.fields["IKN"])

        # Ihale Adi
        scroll_basic_layout.addWidget(QLabel("<b>Ihale Adi:</b>"))
        self.fields["Ihale Adi"] = QLineEdit()
        self.fields["Ihale Adi"].setPlaceholderText("İhale adını giriniz")
        scroll_basic_layout.addWidget(self.fields["Ihale Adi"])

        # Yuklenici Firma
        scroll_basic_layout.addWidget(QLabel("<b>Yuklenici Firma:</b>"))
        self.fields["Yuklenici Firma"] = QLineEdit()
        self.fields["Yuklenici Firma"].setPlaceholderText("Yüklenici Firma bilgisini giriniz")

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT `Yuklenici Firma` FROM data WHERE `Yuklenici Firma` IS NOT NULL AND `Yuklenici Firma` != ''")
            firm_names = [row[0] for row in cursor.fetchall() if row[0]]
            conn.close()
            if firm_names:
                completer = QCompleter(firm_names, self)
                completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
                completer.setFilterMode(Qt.MatchFlag.MatchContains)
                self.fields["Yuklenici Firma"].setCompleter(completer)
        except Exception as e:
            print("Completer error:", e)

        scroll_basic_layout.addWidget(self.fields["Yuklenici Firma"])

        # Sözleşme Tutarı
        scroll_basic_layout.addWidget(QLabel("<b>Sözleşme Tutarı (TL):</b>"))
        self.fields["Sözleşme Tutarı (TL)"] = QLineEdit()
        self.fields["Sözleşme Tutarı (TL)"].setPlaceholderText("Ör. 123.456.789,00")
        regex = QRegularExpression("[0-9.,]+")
        validator = QRegularExpressionValidator(regex)
        self.fields["Sözleşme Tutarı (TL)"].setValidator(validator)
        self.fields["Sözleşme Tutarı (TL)"].textChanged.connect(lambda text: format_currency_input(self.fields["Sözleşme Tutarı (TL)"], text))
        scroll_basic_layout.addWidget(self.fields["Sözleşme Tutarı (TL)"])

        # Parti Miktarı
        scroll_basic_layout.addWidget(QLabel("<b>Malzeme Miktarı (Her parti için kaydedilecek miktar):</b>"))
        self.fields["Parti Miktarı"] = QLineEdit()
        self.fields["Parti Miktarı"].setPlaceholderText("Örn: 5.000")
        regex = QRegularExpression("[0-9.,]+")
        validator = QRegularExpressionValidator(regex)
        self.fields["Parti Miktarı"].setValidator(validator)
        self.fields["Parti Miktarı"].textChanged.connect(lambda text: format_currency_input(self.fields["Parti Miktarı"], text))
        scroll_basic_layout.addWidget(self.fields["Parti Miktarı"])

        # Parti Sayısı
        scroll_basic_layout.addWidget(QLabel("<b>Toplam Parti Sayısı:</b>"))
        self.fields["Parti Sayısı"] = QLineEdit()
        self.fields["Parti Sayısı"].setText("1")
        self.fields["Parti Sayısı"].setValidator(QIntValidator(1, 1000))
        scroll_basic_layout.addWidget(self.fields["Parti Sayısı"])

        # Termin Aralığı (Gün)
        scroll_basic_layout.addWidget(QLabel("<b>Termin Aralığı (Gün):</b>"))
        self.fields["Termin Aralığı (Gün)"] = QLineEdit()
        self.fields["Termin Aralığı (Gün)"].setText("30")
        self.fields["Termin Aralığı (Gün)"].setValidator(QIntValidator(1, 365))
        scroll_basic_layout.addWidget(self.fields["Termin Aralığı (Gün)"])

        # Sözleşme Tarihi
        scroll_basic_layout.addWidget(QLabel("<b>Sözleşme Tarihi:</b>"))
        self.date_edit = QDateEdit()
        self.date_edit.setCalendarPopup(True)
        self.date_edit.setDate(QDate.currentDate())
        self.date_edit.setDisplayFormat("dd.MM.yyyy")
        self.date_edit.dateChanged.connect(self.on_sozlesme_date_changed)
        scroll_basic_layout.addWidget(self.date_edit)
        self.fields["Sözleşme Tarihi"] = self.date_edit

        # İşe Başlama Tarihi
        scroll_basic_layout.addWidget(QLabel("<b>İşe Başlama Tarihi:</b>"))
        self.ise_baslama = QDateEdit()
        self.ise_baslama.setCalendarPopup(True)
        self.ise_baslama.setDate(QDate.currentDate().addDays(1))
        scroll_basic_layout.addWidget(self.ise_baslama)

        scroll_basic_layout.addStretch()
        scroll_basic.setWidget(scroll_basic_content)
        layout_basic.addWidget(scroll_basic)
        self.tabs.addTab(tab_basic, "📦 Temel Bilgiler")

        # 2. SEKME: DETAYLI BİLGİLER
        tab_adv = QWidget()
        layout_adv = QVBoxLayout(tab_adv)
        scroll_adv = QScrollArea()
        scroll_adv.setWidgetResizable(True)
        scroll_adv_content = QWidget()
        scroll_adv_layout = QVBoxLayout(scroll_adv_content)
        scroll_adv_layout.setSpacing(15)

        scroll_adv_layout.addWidget(QLabel("<b>İhale Türü:</b>"))
        self.ihale_turu = QComboBox()
        self.ihale_turu.setEditable(True)
        turu_list = get_ihale_turu_list()
        self.ihale_turu.addItem("")
        if turu_list:
            self.ihale_turu.addItems(turu_list)
        self.ihale_turu.setCurrentIndex(0)
        scroll_adv_layout.addWidget(self.ihale_turu)

        scroll_adv_layout.addWidget(QLabel("<b>İhale Usulü:</b>"))
        self.ihale_usulu = QComboBox()
        self.ihale_usulu.setEditable(True)
        usul_list = get_ihale_usulu_list()
        self.ihale_usulu.addItem("")
        if usul_list:
            self.ihale_usulu.addItems(usul_list)
        self.ihale_usulu.setCurrentIndex(0)
        scroll_adv_layout.addWidget(self.ihale_usulu)

        scroll_adv_layout.addWidget(QLabel("<b>Yaklaşık Maliyet:</b>"))
        self.yak_maliyet = QLineEdit()
        self.yak_maliyet.setValidator(QRegularExpressionValidator(QRegularExpression("[0-9.,]+")))
        self.yak_maliyet.textChanged.connect(lambda text: format_currency_input(self.yak_maliyet, text))
        scroll_adv_layout.addWidget(self.yak_maliyet)

        scroll_adv_layout.addWidget(QLabel("<b>İhale Tarihi:</b>"))
        self.ihale_tarihi = QDateEdit()
        self.ihale_tarihi.setCalendarPopup(True)
        self.ihale_tarihi.setDate(QDate.currentDate())
        scroll_adv_layout.addWidget(self.ihale_tarihi)

        scroll_adv_layout.addWidget(QLabel("<b>Cari No:</b>"))
        self.cari_no = QLineEdit()
        scroll_adv_layout.addWidget(self.cari_no)

        scroll_adv_layout.addWidget(QLabel("<b>Proje No:</b>"))
        self.proje_no = QLineEdit()
        scroll_adv_layout.addWidget(self.proje_no)

        scroll_adv_layout.addWidget(QLabel("<b>Kart No:</b>"))
        self.kart_no = QLineEdit()
        scroll_adv_layout.addWidget(self.kart_no)

        scroll_adv_layout.addWidget(QLabel("<b>Malzeme Detayı:</b>"))
        self.malzeme_detay = QTextEdit()
        self.malzeme_detay.setFixedHeight(80)
        scroll_adv_layout.addWidget(self.malzeme_detay)

        scroll_adv_layout.addStretch()
        scroll_adv.setWidget(scroll_adv_content)
        layout_adv.addWidget(scroll_adv)
        self.tabs.addTab(tab_adv, "🛠️ Detaylı Bilgiler")

        # Butonlar
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Kaydet")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("İptal")
        buttons.accepted.connect(self.process_and_save)
        buttons.rejected.connect(self.reject)
        main_layout.addWidget(buttons)

    def on_sozlesme_date_changed(self, date):
        if hasattr(self, 'ise_baslama'):
            self.ise_baslama.setDate(date.addDays(1))

    def process_and_save(self):
        try:
            ikn = self.fields["IKN"].text()
            ihale = self.fields["Ihale Adi"].text()
            firma = self.fields["Yuklenici Firma"].text()

        # Turkish Currency Parsing: Remove dots, replace comma with dot
            tutar_str = self.fields["Sözleşme Tutarı (TL)"].text()
            toplam_tutar = parse_money(tutar_str)

            parti_sayisi = int(self.fields["Parti Sayısı"].text())
            parti_miktari = parse_money(self.fields["Parti Miktarı"].text())
            termin_araligi = int(self.fields["Termin Aralığı (Gün)"].text() or "30")

            # Date Handling
            sozlesme_tarihi_qdate = self.fields["Sözleşme Tarihi"].date()
            sozlesme_tarihi = datetime(sozlesme_tarihi_qdate.year(), sozlesme_tarihi_qdate.month(), sozlesme_tarihi_qdate.day())
            sozlesme_tarihi_str = sozlesme_tarihi.strftime("%Y-%m-%d")

            # İlk parti teslim tarihi = Sözleşme Tarihi + Termin Aralığı
            ilk_teslim_tarihi = sozlesme_tarihi + timedelta(days=termin_araligi)

            # İşe Başlama Tarihi = Sözleşme Tarihi + 1 gün
            ise_baslama_tarihi = sozlesme_tarihi + timedelta(days=1)
            ise_baslama_tarihi_str = ise_baslama_tarihi.strftime("%Y-%m-%d")

            # Detaylı Bilgiler
            ihale_turu_val = self.ihale_turu.currentText()
            ihale_usulu_val = self.ihale_usulu.currentText()
            yak_maliyet_val = parse_money(self.yak_maliyet.text())
            ihale_tarihi_str = self.ihale_tarihi.date().toString("yyyy-MM-dd")
            cari_no_val = self.cari_no.text()
            proje_no_val = self.proje_no.text()
            kart_no_val = self.kart_no.text()
            malzeme_detay_val = self.malzeme_detay.toPlainText()

            parti_tutari = toplam_tutar / parti_sayisi

            timestamp = datetime.now().strftime("%d.%m.%Y %H:%M")
            audit_info = f"Kayıt: {Session.user} ({timestamp})"

            conn = get_db_connection()
            cursor = conn.cursor()

            # Aynı IKN & Firma birleşimi var mı kontrol et
            cursor.execute("SELECT COUNT(*) FROM data WHERE `IKN`=? AND `Yuklenici Firma`=?", (ikn, firma))
            existing = cursor.fetchone()[0]
            if existing > 0:
                reply = QMessageBox.question(self, "Uyarı",
                    f"Bu IKN ({ikn}) ve Firma ({firma}) birleşimiyle zaten {existing} kayıt bulunuyor.\n\n"
                    "Devam etmek istiyor musunuz?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.No:
                    conn.close()
                    return

            for i in range(1, parti_sayisi + 1):
                teslim_tarihi = (ilk_teslim_tarihi + timedelta(days=termin_araligi*(i-1))).strftime("%Y-%m-%d")
                teslim_dt = datetime.strptime(teslim_tarihi, "%Y-%m-%d")
                parti_suresi_int = (teslim_dt - ise_baslama_tarihi).days + 1
                parti_suresi_str = f"{parti_suresi_int} Gün"
                cursor.execute("""
                    INSERT INTO data
                    (`IKN`, `Yuklenici Firma`, `Ihale Adi`, `Parti No`, `Parti Son Teslim Tarihi`, `Parti Miktari`, `Parti Tutari`,
                     `Ambar teslimi gerceklesti`, `Testler basladi`, `Test sonuclari geldi`, `Muayene - Kabul  Evragi imzada`, `Kabul Yapildi`, `Odeme Emri Hazirlandi`, `Aciklama`, `SonGuncelleme`, `Sozlesme Tarihi`, `Ise Baslama Tarihi`, `Parti Teslim Suresi`,
                     `Ihale Turu`, `Ihale Usulu`, `Yak. Maliyet`, `Ihale Tarihi`, `Cari No`, `Proje No`, `Kart No`, `Malzeme Detayi`)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, 0, '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (ikn, firma, ihale, i, teslim_tarihi, parti_miktari, parti_tutari, audit_info, sozlesme_tarihi_str, ise_baslama_tarihi_str, parti_suresi_str,
                      ihale_turu_val, ihale_usulu_val, yak_maliyet_val, ihale_tarihi_str, cari_no_val, proje_no_val, kart_no_val, malzeme_detay_val))

            log_action("Kayıt Oluşturma", f"IKN: {ikn}, Firma: {firma}, Parti Sayısı: {parti_sayisi}")
            conn.commit()
            conn.close()
            self.accept()
        except Exception as e:
            if 'conn' in locals(): conn.close()
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
                "SELECT MAX(CAST(`Parti No` AS INTEGER)) FROM data WHERE `IKN` = ? AND `Yuklenici Firma` = ? AND `Parti No` GLOB '[0-9]*'",
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
            miktar = parse_money(self.miktar_edit.text())
            if miktar == int(miktar):
                miktar = int(miktar)
            tutar = parse_money(self.amount_edit.text())
            aciklama = self.desc_edit.text()
            timestamp = datetime.now().strftime("%d.%m.%Y %H:%M")
            audit_info = f"Kayıt: {Session.user} ({timestamp})"

            conn = get_db_connection()
            cursor = conn.cursor()

            # Mevcut kayıtlardan ortak alanları miras al
            cursor.execute("""
                SELECT `Sozlesme Tarihi`, `Ise Baslama Tarihi`, `Parti Teslim Suresi`,
                       `Ihale Turu`, `Ihale Usulu`, `Yak. Maliyet`, `Ihale Tarihi`,
                       `Cari No`, `Proje No`, `Kart No`, `Malzeme Detayi`
                FROM data WHERE `IKN` = ? AND `Yuklenici Firma` = ?
                AND `Sozlesme Tarihi` IS NOT NULL AND `Sozlesme Tarihi` != ''
                LIMIT 1
            """, (self.ikn, self.firma))
            existing = cursor.fetchone()
            sozlesme_tarihi = existing[0] if existing else None
            ise_baslama_tarihi = existing[1] if existing else None
            parti_teslim_suresi = existing[2] if existing else None
            ihale_turu = existing[3] if existing else None
            ihale_usulu = existing[4] if existing else None
            yak_maliyet = existing[5] if existing else None
            ihale_tarihi = existing[6] if existing else None
            cari_no = existing[7] if existing else None
            proje_no = existing[8] if existing else None
            kart_no = existing[9] if existing else None
            malzeme_detay = existing[10] if existing else None

            for i in range(sayisi):
                parti_no = self.next_batch_no + i
                teslim_tarihi = (ilk_tarih + timedelta(days=termin * i)).strftime("%Y-%m-%d")
                teslim_dt = datetime.strptime(teslim_tarihi, "%Y-%m-%d")
                if ise_baslama_tarihi:
                    try:
                        baslama_dt = datetime.strptime(str(ise_baslama_tarihi)[:10], "%Y-%m-%d")
                        parti_suresi_hesap = (teslim_dt - baslama_dt).days + 1
                        parti_teslim_suresi = f"{parti_suresi_hesap} Gün"
                    except:
                        parti_teslim_suresi = existing[2] if existing else None
                else:
                    parti_teslim_suresi = existing[2] if existing else None
                cursor.execute("""
                    INSERT INTO data
                    (`IKN`, `Yuklenici Firma`, `Ihale Adi`, `Parti No`,
                     `Parti Son Teslim Tarihi`, `Parti Miktari`, `Parti Tutari`,
                     `Ambar teslimi gerceklesti`, `Testler basladi`,
                     `Test sonuclari geldi`, `Muayene - Kabul  Evragi imzada`,
                     `Kabul Yapildi`, `Odeme Emri Hazirlandi`, `Aciklama`, `SonGuncelleme`,
                     `Sozlesme Tarihi`, `Ise Baslama Tarihi`, `Parti Teslim Suresi`,
                     `Ihale Turu`, `Ihale Usulu`, `Yak. Maliyet`, `Ihale Tarihi`,
                     `Cari No`, `Proje No`, `Kart No`, `Malzeme Detayi`)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (self.ikn, self.firma, self.ihale, parti_no,
                      teslim_tarihi, miktar, tutar, aciklama, audit_info,
                      sozlesme_tarihi, ise_baslama_tarihi, parti_teslim_suresi,
                      ihale_turu, ihale_usulu, yak_maliyet, ihale_tarihi,
                      cari_no, proje_no, kart_no, malzeme_detay))

            conn.commit()
            conn.close()
            log_action("Parti Ekleme",
                       f"IKN: {self.ikn} | Firma: {self.firma} | "
                       f"Parti No: {self.next_batch_no}–{self.next_batch_no + sayisi - 1} | "
                       f"Adet: {sayisi} | Termin: {termin} gün | "
                       f"Miktar: {self.miktar_edit.text()} | Tutar: {self.amount_edit.text()} | "
                       f"Açıklama: {self.desc_edit.text()}")
            self.accept()
        except Exception as e:
            if 'conn' in locals(): conn.close()
            QMessageBox.critical(self, "Hata", f"Parti eklenemedi:\n{e}")

# --- DÜZENLEME PENCERESİ ---
class EditDialog(QDialog):
    def __init__(self, record, parent=None, simplified=False):
        super().__init__(parent)
        self.record = record
        self.rowid = record[0]
        self.simplified = simplified
        self.setWindowTitle("Hızlı Durum Güncelle" if simplified else "Kayıt Düzenle")
        self.resize(700, 600)
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)

        edit_style = "background-color: white; color: #1e293b; border: 1px solid #94a3b8; border-radius: 6px; padding: 6px;"
        header_bg = "#1e293b"
        header_border = "#334155"

        # Başlık Bilgileri
        title_color = "#818cf8" # Light Indigo
        val_color = "#f8fafc"   # Off-white
        header_text = (f"<span style='color:{title_color}; font-weight:bold;'>IKN:</span> {self.record[1] if len(self.record) > 1 else '?'} | "
                       f"<span style='color:{title_color}; font-weight:bold;'>Firma:</span> {self.record[2] if len(self.record) > 2 else '?'}<br>"
                       f"<span style='color:{title_color}; font-weight:bold;'>İhale:</span> {self.record[3] if len(self.record) > 3 else '?'} (Parti {self.record[4] if len(self.record) > 4 else '?'})")

        header_lbl = QLabel(header_text)
        header_lbl.setWordWrap(True)
        header_lbl.setStyleSheet(f"font-size: 13px; color: {val_color}; padding: 8px; background: {header_bg}; border-radius: 6px; border: 1px solid {header_border};")
        main_layout.addWidget(header_lbl)

        # --- TAB YAPISI ---
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # 1. SEKME: TEMEL BİLGİLER
        tab_basic = QWidget()
        layout_basic = QVBoxLayout(tab_basic)

        scroll_basic = QScrollArea()
        scroll_basic.setWidgetResizable(True)
        scroll_basic_content = QWidget()
        scroll_basic_layout = QVBoxLayout(scroll_basic_content)

        self.parti_no_edit = QLineEdit(str(self.record[4]) if len(self.record) > 4 else "1")
        self.parti_no_edit.setValidator(QIntValidator(1, 1000))
        self.parti_no_edit.setStyleSheet(edit_style)
        scroll_basic_layout.addWidget(QLabel("Parti No:"))
        scroll_basic_layout.addWidget(self.parti_no_edit)

        miktar_val = format_number(self.record[16]) if len(self.record) > 16 and self.record[16] else ""
        self.miktar_edit = QLineEdit(miktar_val)
        self.miktar_edit.setValidator(QRegularExpressionValidator(QRegularExpression(r"[0-9\.,]*")))
        self.miktar_edit.setStyleSheet(edit_style)
        self.miktar_edit.textEdited.connect(lambda text: format_number_edit(self.miktar_edit, text))
        scroll_basic_layout.addWidget(QLabel("Parti Miktarı:"))
        scroll_basic_layout.addWidget(self.miktar_edit)

        self.tutar_edit = QLineEdit(format_money(self.record[6])) if len(self.record) > 6 else QLineEdit("0,00")
        self.tutar_edit.setValidator(QRegularExpressionValidator(QRegularExpression(r"[0-9\.,]*")))
        self.tutar_edit.setStyleSheet(edit_style)
        self.tutar_edit.textEdited.connect(lambda text: format_number_edit(self.tutar_edit, text))
        scroll_basic_layout.addWidget(QLabel("Parti Tutarı:"))
        scroll_basic_layout.addWidget(self.tutar_edit)

        self.tarih_edit = QDateEdit()
        self.tarih_edit.setCalendarPopup(True)
        self.tarih_edit.setStyleSheet(edit_style)
        try:
            if len(self.record) > 5 and self.record[5]:
                d = datetime.strptime(str(self.record[5])[:10], "%Y-%m-%d")
                self.tarih_edit.setDate(QDate(d.year, d.month, d.day))
        except:
            self.tarih_edit.setDate(QDate.currentDate())
        scroll_basic_layout.addWidget(QLabel("Teslim Tarihi:"))
        scroll_basic_layout.addWidget(self.tarih_edit)

        scroll_basic_layout.addWidget(QLabel("Malzeme Detayı:"))
        self.malzeme_detayi_edit = QTextEdit()
        self.malzeme_detayi_edit.setFixedHeight(100)
        self.malzeme_detayi_edit.setStyleSheet(edit_style)
        malzeme_val = str(self.record[18]) if len(self.record) > 18 and self.record[18] else ""
        self.malzeme_detayi_edit.setPlainText(malzeme_val)
        scroll_basic_layout.addWidget(self.malzeme_detayi_edit)

        scroll_basic.setWidget(scroll_basic_content)
        layout_basic.addWidget(scroll_basic)
        if not self.simplified:
            self.tabs.addTab(tab_basic, "📦 Temel Bilgiler")

        # 2. SEKME: İŞLEM ADIMLARI
        tab_steps = QWidget()
        layout_steps = QVBoxLayout(tab_steps)

        scroll_steps = QScrollArea()
        scroll_steps.setWidgetResizable(True)
        scroll_steps_content = QWidget()
        scroll_steps_layout = QVBoxLayout(scroll_steps_content)

        self.cb_list = {}
        steps = [
            ("1. Ambar Teslimi Gerçekleşti", 7),
            ("2. Heyet Başkanına Haber Verildi", 19),
            ("3. Testler Başladı", 8),
            ("4. Test Sonuçları Geldi", 9),
            ("5. Kabul Raporu imzada", 10),
            ("6. Kabul Yapıldı", 11),
            ("7. Ödeme Belgesi Oluşturuldu", 13)
        ]

        self.test_start_edit = MultiSelectComboBox()
        test_start_val = str(self.record[20]) if len(self.record) > 20 and self.record[20] else ""
        self.test_start_edit.add_labs(get_labs(), test_start_val)
        self.test_start_edit.setStyleSheet(edit_style)
        self.test_start_edit.setFixedWidth(250)

        self.test_result_edit = MultiSelectComboBox()
        test_result_val = str(self.record[21]) if len(self.record) > 21 and self.record[21] else ""
        self.test_result_edit.add_labs(get_labs(), test_result_val)
        self.test_result_edit.setStyleSheet(edit_style)
        self.test_result_edit.setFixedWidth(250)

        steps_grid = QGridLayout()
        steps_grid.setVerticalSpacing(6)

        for i, (text, idx) in enumerate(steps):
            steps_grid.setRowMinimumHeight(i, 28)
            is_checked = (len(self.record) > idx and _is_checked(self.record[idx]))
            cb = QCheckBox(text)
            cb.setChecked(is_checked)
            cb.setStyleSheet("font-size: 13px; font-weight: bold;")
            self.cb_list[text] = cb

            steps_grid.addWidget(cb, i, 0)

            if "Testler Başladı" in text:
                lab_layout = QHBoxLayout()
                lab_layout.setContentsMargins(0, 0, 0, 0)
                lab_layout.addWidget(QLabel("Test Laboratuvar(lar)ı:___"))
                lab_layout.addWidget(self.test_start_edit)
                lab_layout.addStretch()
                steps_grid.addLayout(lab_layout, i, 1)
            elif "Test Sonuçları Geldi" in text:
                res_layout = QHBoxLayout()
                res_layout.setContentsMargins(0, 0, 0, 0)
                res_layout.addWidget(QLabel("Sonuç Laboratuvar(lar)ı:_"))
                res_layout.addWidget(self.test_result_edit)
                res_layout.addStretch()
                steps_grid.addLayout(res_layout, i, 1)

        scroll_steps_layout.addLayout(steps_grid)

        # --- Açıklama ---
        scroll_steps_layout.addSpacing(15)
        aciklama_row = QHBoxLayout()
        aciklama_row.addWidget(QLabel("<b>Açıklama:</b>"))
        aciklama_row.addStretch()
        last_upd = str(self.record[15]) if len(self.record) > 15 and self.record[15] else "Bilgi yok"
        self.last_upd_label = QLabel(f"ℹ️ Son İşlem: {last_upd}")
        self.last_upd_label.setStyleSheet("color: #6366f1; font-size: 11px; font-weight: bold;")
        aciklama_row.addWidget(self.last_upd_label)
        scroll_steps_layout.addLayout(aciklama_row)

        self.aciklama_edit = QTextEdit()
        self.aciklama_edit.setFixedHeight(100)
        self.aciklama_edit.setStyleSheet(edit_style)
        raw_desc = str(self.record[14]) if len(self.record) > 14 and self.record[14] else ""
        if " | Düzenleme:" in raw_desc: raw_desc = raw_desc.split(" | Düzenleme:")[0]
        elif "Kayıt: " in raw_desc and "(" in raw_desc:
            if raw_desc.startswith("Kayıt: "): raw_desc = ""
        self.aciklama_edit.setPlainText(raw_desc)
        self._original_desc = raw_desc  # Karşılaştırma için temizlenmiş halini sakla
        scroll_steps_layout.addWidget(self.aciklama_edit)

        scroll_steps_layout.addStretch()
        scroll_steps.setWidget(scroll_steps_content)
        layout_steps.addWidget(scroll_steps)
        self.tabs.addTab(tab_steps, "⚙️ İşlem Adımları")

        # --- Sabit Butonlar ---
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("Değişiklikleri Kaydet")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("İptal")
        buttons.accepted.connect(self.save_changes); buttons.rejected.connect(self.reject)
        main_layout.addWidget(buttons)

    def save_changes(self):
        try:
            rowid = self.rowid
            old = self.record
            timestamp = datetime.now().strftime("%d.%m.%Y %H:%M")
            change_details = []

            # Temel Bilgiler (simplified modda sadece mevcut alanları kaydet)
            if not self.simplified:

                new_parti = self.parti_no_edit.text().strip()
                if new_parti != str(old[4]):
                    update_record(rowid, "Parti No", new_parti)
                    change_details.append(f"Parti No: {new_parti}")

                new_miktar = parse_money(self.miktar_edit.text())
                if new_miktar == int(new_miktar):
                    new_miktar = int(new_miktar)
                old_miktar = str(old[16]) if len(old) > 16 and old[16] else ""
                if str(new_miktar) != str(parse_money(old_miktar)):
                    update_record(rowid, "Parti Miktari", new_miktar)
                    change_details.append(f"Miktar: {new_miktar}")

                new_tutar = parse_money(self.tutar_edit.text())
                old_tutar = str(old[6]) if len(old) > 6 and old[6] else ""
                if str(new_tutar) != old_tutar:
                    update_record(rowid, "Parti Tutari", new_tutar)
                    change_details.append(f"Tutar: {new_tutar}")

                qd = self.tarih_edit.date()
                new_tarih = f"{qd.year():04d}-{qd.month():02d}-{qd.day():02d}"
                old_tarih = str(old[5])[:10] if len(old) > 5 and old[5] else ""
                if new_tarih != old_tarih:
                    update_record(rowid, "Parti Son Teslim Tarihi", new_tarih)
                    change_details.append(f"Teslim Tarihi: {new_tarih}")

                new_malzeme = self.malzeme_detayi_edit.toPlainText()
                old_malzeme = str(old[18]) if len(old) > 18 and old[18] else ""
                if new_malzeme != old_malzeme:
                    update_record(rowid, "Malzeme Detayi", new_malzeme)
                    change_details.append("Malzeme Detayı değiştirildi")

            # Açıklama
            new_aciklama = self.aciklama_edit.toPlainText()
            if new_aciklama != getattr(self, '_original_desc', ''):
                update_record(rowid, "Aciklama", new_aciklama)
                change_details.append(f"Açıklama: '{new_aciklama[:50]}...' " if len(new_aciklama) > 50 else f"Açıklama: '{new_aciklama}' ")

            # İşlem Adımları
            step_map = {
                "1. Ambar Teslimi Gerçekleşti": "Ambar teslimi gerceklesti",
                "2. Heyet Başkanına Haber Verildi": "Heyet Baskanina Haber Verildi",
                "3. Testler Başladı": "Testler basladi",
                "4. Test Sonuçları Geldi": "Test sonuclari geldi",
                "5. Kabul Raporu imzada": "Muayene - Kabul  Evragi imzada",
                "6. Kabul Yapıldı": "Kabul Yapildi",
                "7. Ödeme Belgesi Oluşturuldu": "Odeme Emri Hazirlandi"
            }
            step_indices = {
                "1. Ambar Teslimi Gerçekleşti": 7,
                "2. Heyet Başkanına Haber Verildi": 19,
                "3. Testler Başladı": 8,
                "4. Test Sonuçları Geldi": 9,
                "5. Kabul Raporu imzada": 10,
                "6. Kabul Yapıldı": 11,
                "7. Ödeme Belgesi Oluşturuldu": 13
            }

            for text, cb in self.cb_list.items():
                db_col = step_map.get(text)
                idx = step_indices.get(text)
                if db_col and idx is not None:
                    old_val = _is_checked(old[idx]) if len(old) > idx else False
                    new_val = cb.isChecked()
                    if old_val != new_val:
                        update_record(rowid, db_col, 1.0 if new_val else 0.0)
                        status = "onaylandı" if new_val else "onayı kaldırıldı"
                        change_details.append(f"{text.replace('1. ', '').replace('2. ', '').replace('3. ', '').replace('4. ', '').replace('5. ', '').replace('6. ', '').replace('7. ', '')} {status}")

            # Test Laboratuvar Detayları
            new_test_start = self.test_start_edit.get_checked_items()
            old_test_start = str(old[20]) if len(old) > 20 and old[20] else ""
            if new_test_start != old_test_start:
                update_record(rowid, "Testler Basladi Detay", new_test_start)
                change_details.append(f"Test Başlangıç Lab: {new_test_start}")

            new_test_result = self.test_result_edit.get_checked_items()
            old_test_result = str(old[21]) if len(old) > 21 and old[21] else ""
            if new_test_result != old_test_result:
                update_record(rowid, "Test Sonuclari Geldi Detay", new_test_result)
                change_details.append(f"Test Sonuç Lab: {new_test_result}")

            # Audit Log
            audit_log = f"Düzenleme: {Session.user} ({timestamp})"
            update_record(rowid, "SonGuncelleme", audit_log)

            if change_details:
                log_desc = " | ".join(change_details)
                log_action("Kayıt Düzenleme", f"IKN: {old[1]} | Firma: {old[2]} | {log_desc}")
            else:
                log_action("Kayıt Düzenleme", f"IKN: {old[1]} | Firma: {old[2]} | Değişiklik yapılmadı")
            QMessageBox.information(self, "Başarılı", "Kayıt başarıyla güncellendi.")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Kayıt güncellenirken hata oluştu:\n{e}")

class BulkEditDialog(QDialog):
    def __init__(self, records, parent=None):
        super().__init__(parent)
        self.records = records  # List of full record tuples
        self.setWindowTitle(f"Toplu Kayıt Düzenle ({len(records)} kayıt)")
        self.setFixedWidth(725)
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        self.resize(725, 585)

        edit_style = "background-color: white; color: #1e293b; border: 1px solid #94a3b8; border-radius: 6px; padding: 6px;"

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # 1. SEKME: TEMEL BİLGİLER
        tab_basic = QWidget()
        layout_basic = QVBoxLayout(tab_basic)

        scroll_basic = QScrollArea()
        scroll_basic.setWidgetResizable(True)
        scroll_basic_content = QWidget()
        scroll_basic_layout = QVBoxLayout(scroll_basic_content)

        # Seçili kayıtlardan varsayılan değerleri belirle
        ikns = set(str(r[1]) for r in self.records if len(r) > 1 and r[1])
        firmas = set(str(r[2]) for r in self.records if len(r) > 2 and r[2])
        ihales = set(str(r[3]) for r in self.records if len(r) > 3 and r[3])

        default_ikn = next(iter(ikns)) if len(ikns) == 1 else ""
        default_firma = next(iter(firmas)) if len(firmas) == 1 else ""
        default_ihale = next(iter(ihales)) if len(ihales) == 1 else ""

        sozlesmes = set(str(r[17]) for r in self.records if len(r) > 17 and r[17])
        default_sozlesme = next(iter(sozlesmes)) if len(sozlesmes) == 1 else ""

        form_layout = QGridLayout()

        self.cb_update_ikn = QCheckBox("İKN'yi Güncelle:")
        self.ikn_edit = QLineEdit(); self.ikn_edit.setText(default_ikn); self.ikn_edit.setEnabled(False); self.ikn_edit.setStyleSheet(edit_style)
        self.cb_update_ikn.toggled.connect(self.ikn_edit.setEnabled)
        form_layout.addWidget(self.cb_update_ikn, 0, 0); form_layout.addWidget(self.ikn_edit, 0, 1)

        self.cb_update_firma = QCheckBox("Yüklenici Firmayı Güncelle:")
        self.firma_edit = QLineEdit(); self.firma_edit.setText(default_firma); self.firma_edit.setEnabled(False); self.firma_edit.setStyleSheet(edit_style)
        self.cb_update_firma.toggled.connect(self.firma_edit.setEnabled)
        form_layout.addWidget(self.cb_update_firma, 1, 0); form_layout.addWidget(self.firma_edit, 1, 1)

        self.cb_update_ihale = QCheckBox("İhale Adını Güncelle:")
        self.ihale_edit = QTextEdit(); self.ihale_edit.setText(default_ihale); self.ihale_edit.setEnabled(False); self.ihale_edit.setStyleSheet(edit_style)
        self.ihale_edit.setFixedHeight(60)
        self.cb_update_ihale.toggled.connect(self.ihale_edit.setEnabled)
        form_layout.addWidget(self.cb_update_ihale, 2, 0); form_layout.addWidget(self.ihale_edit, 2, 1)

        self.cb_update_sozlesme = QCheckBox("Sözleşme Tarihini Güncelle:")
        self.sozlesme_edit = QDateEdit(); self.sozlesme_edit.setCalendarPopup(True); self.sozlesme_edit.setEnabled(False); self.sozlesme_edit.setStyleSheet(edit_style)
        if default_sozlesme:
            try:
                d = datetime.strptime(default_sozlesme[:10], "%Y-%m-%d")
                self.sozlesme_edit.setDate(QDate(d.year, d.month, d.day))
            except: self.sozlesme_edit.setDate(QDate.currentDate())
        else: self.sozlesme_edit.setDate(QDate.currentDate())
        self.cb_update_sozlesme.toggled.connect(self.sozlesme_edit.setEnabled)
        self.sozlesme_edit.dateChanged.connect(self.on_sozlesme_date_changed)
        form_layout.addWidget(self.cb_update_sozlesme, 3, 0); form_layout.addWidget(self.sozlesme_edit, 3, 1)

        self.cb_update_miktar = QCheckBox("Miktarı Güncelle:")
        self.miktar_edit = QLineEdit(); self.miktar_edit.setEnabled(False); self.miktar_edit.setStyleSheet(edit_style)
        self.miktar_edit.setValidator(QRegularExpressionValidator(QRegularExpression(r"[0-9\.,]*")))
        self.miktar_edit.textEdited.connect(lambda text: format_number_edit(self.miktar_edit, text))
        self.cb_update_miktar.toggled.connect(self.miktar_edit.setEnabled)
        form_layout.addWidget(self.cb_update_miktar, 4, 0); form_layout.addWidget(self.miktar_edit, 4, 1)

        self.cb_update_malzeme = QCheckBox("Malzeme Detayını Güncelle:")
        self.malzeme_edit = QTextEdit(); self.malzeme_edit.setFixedHeight(80); self.malzeme_edit.setEnabled(False); self.malzeme_edit.setStyleSheet(edit_style)
        self.cb_update_malzeme.toggled.connect(self.malzeme_edit.setEnabled)
        form_layout.addWidget(self.cb_update_malzeme, 5, 0); form_layout.addWidget(self.malzeme_edit, 5, 1)

        self.cb_update_tutar = QCheckBox("Tutarı Güncelle:")
        self.tutar_edit = QLineEdit(); self.tutar_edit.setEnabled(False); self.tutar_edit.setStyleSheet(edit_style)
        self.tutar_edit.setValidator(QRegularExpressionValidator(QRegularExpression(r"[0-9\.,]*")))
        self.tutar_edit.textEdited.connect(lambda text: format_number_edit(self.tutar_edit, text))
        self.cb_update_tutar.toggled.connect(self.tutar_edit.setEnabled)
        form_layout.addWidget(self.cb_update_tutar, 6, 0); form_layout.addWidget(self.tutar_edit, 6, 1)

        self.cb_update_aciklama = QCheckBox("Açıklamayı Güncelle:")
        self.aciklama_edit = QTextEdit(); self.aciklama_edit.setEnabled(False); self.aciklama_edit.setStyleSheet(edit_style)
        self.aciklama_edit.setFixedHeight(75)
        self.cb_update_aciklama.toggled.connect(self.aciklama_edit.setEnabled)
        form_layout.addWidget(self.cb_update_aciklama, 7, 0); form_layout.addWidget(self.aciklama_edit, 7, 1)

        scroll_basic_layout.addLayout(form_layout); scroll_basic_layout.addStretch()
        scroll_basic.setWidget(scroll_basic_content); layout_basic.addWidget(scroll_basic)
        self.tabs.addTab(tab_basic, "📦 Temel Bilgiler")

        # 2. SEKME: İŞLEM ADIMLARI
        tab_steps = QWidget()
        layout_steps = QVBoxLayout(tab_steps)
        scroll_steps = QScrollArea(); scroll_steps.setWidgetResizable(True)
        scroll_steps_content = QWidget(); scroll_steps_layout = QVBoxLayout(scroll_steps_content)

        scroll_steps_layout.addWidget(QLabel("<b>İşlem Adımları (Toplu Durum Güncelleme):</b>"))
        scroll_steps_layout.addWidget(QLabel("<small><i>( Kare: Değiştirme | ✓: Onayla | Boş: Onayı İptal Et )</i></small>"))
        scroll_steps_layout.addSpacing(10)

        self.status_checks = {}
        steps = [
            ("1. Ambar Teslimi Gerçekleşti", 7), ("2. Heyet Başkanına Haber Verildi", 19),
            ("3. Testler Başladı", 8), ("4. Test Sonuçları Geldi", 9),
            ("5. Kabul Raporu imzada", 10), ("6. Kabul Yapıldı", 11), ("7. Ödeme Belgesi Oluşturuldu", 13)
        ]

        self.cb_update_test_start = QCheckBox("Test Laboratuvarı:___")
        self.test_start_bulk_edit = MultiSelectComboBox()
        self.test_start_bulk_edit.add_labs(get_labs())
        self.test_start_bulk_edit.setEnabled(False); self.test_start_bulk_edit.setStyleSheet(edit_style); self.test_start_bulk_edit.setFixedWidth(250)
        self.cb_update_test_start.toggled.connect(self.test_start_bulk_edit.setEnabled)

        self.cb_update_test_result = QCheckBox("Sonuç Laboratuvarı:_")
        self.test_result_bulk_edit = MultiSelectComboBox()
        self.test_result_bulk_edit.add_labs(get_labs())
        self.test_result_bulk_edit.setEnabled(False); self.test_result_bulk_edit.setStyleSheet(edit_style); self.test_result_bulk_edit.setFixedWidth(250)
        self.cb_update_test_result.toggled.connect(self.test_result_bulk_edit.setEnabled)

        steps_grid = QGridLayout()
        steps_grid.setVerticalSpacing(12)
        for i, (text, idx) in enumerate(steps):
            steps_grid.setRowMinimumHeight(i, 45)
            cb = QCheckBox(text)
            cb.setTristate(True); cb.setCheckState(Qt.CheckState.PartiallyChecked)
            cb.setStyleSheet("font-size: 13px; font-weight: bold;")
            self.status_checks[text] = cb
            steps_grid.addWidget(cb, i, 0)
            if "Testler Başladı" in text:
                row = QHBoxLayout(); row.setContentsMargins(0, 0, 0, 0)
                row.addSpacing(20); row.addWidget(self.cb_update_test_start); row.addWidget(self.test_start_bulk_edit)
                row.addStretch()
                steps_grid.addLayout(row, i, 1)
            elif "Test Sonuçları Geldi" in text:
                row = QHBoxLayout(); row.setContentsMargins(0, 0, 0, 0)
                row.addSpacing(20); row.addWidget(self.cb_update_test_result); row.addWidget(self.test_result_bulk_edit)
                row.addStretch()
                steps_grid.addLayout(row, i, 1)
        scroll_steps_layout.addLayout(steps_grid)

        scroll_steps_layout.addStretch()
        scroll_steps.setWidget(scroll_steps_content); layout_steps.addWidget(scroll_steps)
        self.tabs.addTab(tab_steps, "⚙️ İşlem Adımları")

        # 3. SEKME: DETAYLI BİLGİLER
        tab_adv = QWidget()
        layout_adv = QVBoxLayout(tab_adv)
        scroll_adv = QScrollArea(); scroll_adv.setWidgetResizable(True)
        scroll_adv_content = QWidget(); scroll_adv_layout = QVBoxLayout(scroll_adv_content)
        adv_grid = QGridLayout()
        adv_grid.setVerticalSpacing(15)

        # Seçili kayıtlardan varsayılan değerleri belirle
        def common_value(idx):
            vals = set(str(r[idx]) for r in self.records if len(r) > idx and r[idx])
            return next(iter(vals)) if len(vals) == 1 else ""

        def common_date(idx):
            vals = set(str(r[idx])[:10] for r in self.records if len(r) > idx and r[idx])
            return next(iter(vals)) if len(vals) == 1 else ""

        adv_fields = [
            ("cb_update_turu", "turu_edit", "İhale Türü:", None, 22),
            ("cb_update_usulu", "usulu_edit", "İhale Usulü:", None, 23),
            ("cb_update_yak_maliyet", "yak_maliyet_edit", "Yaklaşık Maliyet:", None, 24),
            ("cb_update_ihale_tarihi", "ihale_tarihi_edit", "İhale Tarihi:", "date", 25),
            ("cb_update_ise_baslama", "ise_baslama_edit", "İşe Başlama Tarihi:", "date", 26),
            ("cb_update_ambar", "ambar_edit", "Teslim Ambarı:", None, 31),
            ("cb_update_cari", "cari_edit", "Cari No:", None, 28),
            ("cb_update_proje", "proje_edit", "Proje No:", None, 29),
            ("cb_update_kart", "kart_edit", "Kart No:", None, 30)
        ]

        for i, (cb_name, edit_name, label, field_type, db_idx) in enumerate(adv_fields):
            cb = QCheckBox(label)
            if field_type == "date":
                edit = QDateEdit(); edit.setCalendarPopup(True)
                default_date_str = common_date(db_idx)
                if default_date_str:
                    try:
                        d = datetime.strptime(default_date_str, "%Y-%m-%d")
                        edit.setDate(QDate(d.year, d.month, d.day))
                    except:
                        edit.setDate(QDate.currentDate())
                else:
                    edit.setDate(QDate.currentDate())
                if edit_name == "ise_baslama_edit" and hasattr(self, "sozlesme_edit"):
                    edit.setDate(self.sozlesme_edit.date().addDays(1))
            elif "turu_edit" == edit_name:
                edit = QComboBox()
                edit.setEditable(True)
                edit.addItems(get_ihale_turu_list())
                default_val = common_value(db_idx)
                edit.setCurrentText(default_val)
            elif "usulu_edit" == edit_name:
                edit = QComboBox()
                edit.setEditable(True)
                edit.addItems(get_ihale_usulu_list())
                default_val = common_value(db_idx)
                edit.setCurrentText(default_val)
            elif "ambar_edit" == edit_name:
                edit = QComboBox()
                edit.setEditable(True)
                edit.addItems(get_ambar_list())
                default_val = common_value(db_idx)
                if default_val:
                    edit.setCurrentText(default_val)
                else:
                    edit.setCurrentIndex(-1)
            else:
                edit = QLineEdit()
                raw_val = common_value(db_idx)
                if raw_val and edit_name in ["cari_edit", "proje_edit", "kart_edit"]:
                    clean = raw_val.replace('.', '')
                    if clean.isdigit():
                        raw_val = "{:,}".format(int(clean)).replace(',', '.')
                if raw_val and edit_name == "yak_maliyet_edit":
                    raw_val = format_number(raw_val)
                edit.setText(raw_val)

            edit.setEnabled(False); edit.setStyleSheet(edit_style)
            cb.toggled.connect(edit.setEnabled)
            setattr(self, cb_name, cb); setattr(self, edit_name, edit)
            adv_grid.addWidget(cb, i, 0); adv_grid.addWidget(edit, i, 1)

        self.yak_maliyet_edit.setValidator(QRegularExpressionValidator(QRegularExpression("[0-9.,]+")))
        self.yak_maliyet_edit.textChanged.connect(lambda text: format_currency_input(self.yak_maliyet_edit, text))

        for edit_name in ["cari_edit", "proje_edit", "kart_edit"]:
            edit = getattr(self, edit_name, None)
            if edit:
                edit.setValidator(QRegularExpressionValidator(QRegularExpression("[0-9.,]+")))
                edit.textChanged.connect(lambda text, e=edit: format_currency_input(e, text))

        scroll_adv_layout.addLayout(adv_grid); scroll_adv_layout.addStretch()
        scroll_adv.setWidget(scroll_adv_content); layout_adv.addWidget(scroll_adv)
        self.tabs.addTab(tab_adv, "🛠️ Detaylı Bilgiler")

        # Butonlar
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("Toplu Değişiklikleri Kaydet")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("İptal")
        buttons.accepted.connect(self.save_changes); buttons.rejected.connect(self.reject)
        main_layout.addWidget(buttons)

    def on_sozlesme_date_changed(self, date):
        """Sözleşme tarihi değiştiğinde işe başlama tarihini otomatik +1 gün yapar."""
        if hasattr(self, 'ise_baslama_edit'):
            self.ise_baslama_edit.setDate(date.addDays(1))

    def save_changes(self):
        reply = QMessageBox.question(self, "Toplu İşlem Onayı", f"Seçili {len(self.records)} kaydı güncellemek istediğinize emin misiniz?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            changes_summary = []
            value_details = []

            do_ikn = self.cb_update_ikn.isChecked()
            new_ikn = self.ikn_edit.text() if do_ikn else None
            if do_ikn:
                changes_summary.append("IKN")
                value_details.append(f"IKN: {new_ikn}")

            do_firma = self.cb_update_firma.isChecked()
            new_firma = self.firma_edit.text() if do_firma else None
            if do_firma:
                changes_summary.append("Firma")
                value_details.append(f"Firma: {new_firma}")

            do_ihale = self.cb_update_ihale.isChecked()
            new_ihale = self.ihale_edit.toPlainText() if do_ihale else None
            if do_ihale:
                changes_summary.append("İhale Adı")
                value_details.append(f"İhale Adı: {new_ihale[:60]}")

            do_sozlesme = self.cb_update_sozlesme.isChecked()
            new_sozlesme_qdate = self.sozlesme_edit.date()
            new_sozlesme_dt = datetime(new_sozlesme_qdate.year(), new_sozlesme_qdate.month(), new_sozlesme_qdate.day())
            new_sozlesme_str = new_sozlesme_dt.strftime("%Y-%m-%d")
            if do_sozlesme:
                changes_summary.append("Sözleşme Tarihi & Bağlı Teslim Tarihleri")
                value_details.append(f"Sözleşme: {new_sozlesme_str}")

            do_miktar = self.cb_update_miktar.isChecked()
            new_miktar = parse_money(self.miktar_edit.text()) if do_miktar else None
            if new_miktar is not None and new_miktar == int(new_miktar):
                new_miktar = int(new_miktar)
            if do_miktar:
                changes_summary.append("Miktar")
                value_details.append(f"Miktar: {new_miktar}")

            do_malzeme = self.cb_update_malzeme.isChecked()
            new_malzeme = self.malzeme_edit.toPlainText() if do_malzeme else None
            if do_malzeme:
                changes_summary.append("Malzeme Detayı")
                value_details.append(f"Malzeme: {new_malzeme[:60]}")

            do_tutar = self.cb_update_tutar.isChecked()
            new_tutar = parse_money(self.tutar_edit.text()) if do_tutar else None
            if do_tutar:
                changes_summary.append("Tutar")
                value_details.append(f"Tutar: {new_tutar}")

            do_aciklama = self.cb_update_aciklama.isChecked()
            new_aciklama = self.aciklama_edit.toPlainText() if do_aciklama else None
            if do_aciklama:
                changes_summary.append("Açıklama")
                value_details.append(f"Açıklama: {new_aciklama[:60]}")

            do_test_start = self.cb_update_test_start.isChecked()
            new_test_start = self.test_start_bulk_edit.get_checked_items() if do_test_start else None
            if do_test_start:
                changes_summary.append("Testler Başladı Detay")
                value_details.append(f"Test Başlangıç: {new_test_start}")

            do_test_result = self.cb_update_test_result.isChecked()
            new_test_result = self.test_result_bulk_edit.get_checked_items() if do_test_result else None
            if do_test_result:
                changes_summary.append("Test Sonuçları Geldi Detay")
                value_details.append(f"Test Sonuç: {new_test_result}")

            status_updates = {}
            for text, cb in self.status_checks.items():
                state = cb.checkState()
                if state == Qt.CheckState.Checked:
                    status_updates[text] = 1.0
                    changes_summary.append(f"{text} (✓)")
                    clean = text.replace("1. ", "").replace("2. ", "").replace("3. ", "").replace("4. ", "").replace("5. ", "").replace("6. ", "").replace("7. ", "")
                    value_details.append(f"{clean} onaylandı")
                elif state == Qt.CheckState.Unchecked:
                    status_updates[text] = 0.0
                    changes_summary.append(f"{text} (○)")
                    clean = text.replace("1. ", "").replace("2. ", "").replace("3. ", "").replace("4. ", "").replace("5. ", "").replace("6. ", "").replace("7. ", "")
                    value_details.append(f"{clean} onayı kaldırıldı")

            # Gelişmiş Alanların Değişiklik Kontrolü
            if self.cb_update_turu.isChecked():
                changes_summary.append("İhale Türü")
                value_details.append(f"İhale Türü: {self.turu_edit.currentText()}")
            if self.cb_update_usulu.isChecked():
                changes_summary.append("İhale Usulü")
                value_details.append(f"İhale Usulü: {self.usulu_edit.currentText()}")
            if self.cb_update_yak_maliyet.isChecked():
                changes_summary.append("Yak. Maliyet")
                value_details.append(f"Yak. Maliyet: {self.yak_maliyet_edit.text()}")
            if self.cb_update_ihale_tarihi.isChecked():
                changes_summary.append("İhale Tarihi")
                value_details.append(f"İhale Tarihi: {self.ihale_tarihi_edit.date().toString('yyyy-MM-dd')}")
            if self.cb_update_ise_baslama.isChecked():
                changes_summary.append("İşe Başlama Tarihi")
                value_details.append(f"İşe Başlama: {self.ise_baslama_edit.date().toString('yyyy-MM-dd')}")
            if self.cb_update_cari.isChecked():
                changes_summary.append("Cari No")
                value_details.append(f"Cari No: {self.cari_edit.text()}")
            if self.cb_update_proje.isChecked():
                changes_summary.append("Proje No")
                value_details.append(f"Proje No: {self.proje_edit.text()}")
            if self.cb_update_kart.isChecked():
                changes_summary.append("Kart No")
                value_details.append(f"Kart No: {self.kart_edit.text()}")
            if self.cb_update_ambar.isChecked():
                changes_summary.append("Teslim Ambarı")
                value_details.append(f"Teslim Ambarı: {self.ambar_edit.currentText()}")

            if not changes_summary:
                QMessageBox.warning(self, "Uyarı", "Hiçbir değişiklik seçilmedi.")
                return

            timestamp = datetime.now().strftime("%d.%m.%Y %H:%M")
            audit_log = f"Toplu Düzenleme: {Session.user} ({timestamp})"

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("BEGIN")
            try:
                for r in self.records:
                    rowid = r[0]

                    if do_ikn: update_record(rowid, "IKN", new_ikn, cursor)
                    if do_firma: update_record(rowid, "Yuklenici Firma", new_firma, cursor)
                    if do_ihale: update_record(rowid, "Ihale Adi", new_ihale, cursor)

                    if do_sozlesme:
                        old_sozlesme_str = str(r[17]) if len(r) > 17 and r[17] else ""
                        if old_sozlesme_str:
                            try:
                                old_sozlesme_dt = datetime.strptime(old_sozlesme_str[:10], "%Y-%m-%d")
                                delta = (new_sozlesme_dt - old_sozlesme_dt).days
                                if delta != 0:
                                    old_teslim_str = str(r[5])[:10] if len(r) > 5 and r[5] else ""
                                    if old_teslim_str:
                                        old_teslim_dt = datetime.strptime(old_teslim_str, "%Y-%m-%d")
                                        new_teslim_dt = old_teslim_dt + timedelta(days=delta)
                                        new_teslim_str = new_teslim_dt.strftime("%Y-%m-%d")
                                        update_record(rowid, "Parti Son Teslim Tarihi", new_teslim_str, cursor)
                            except: pass
                        update_record(rowid, "Sozlesme Tarihi", new_sozlesme_str, cursor)

                    if do_miktar: update_record(rowid, "Parti Miktari", new_miktar, cursor)
                    if do_malzeme: update_record(rowid, "Malzeme Detayi", new_malzeme, cursor)
                    if do_tutar: update_record(rowid, "Parti Tutari", new_tutar, cursor)
                    if do_aciklama: update_record(rowid, "Aciklama", new_aciklama, cursor)
                    if do_test_start: update_record(rowid, "Testler Basladi Detay", new_test_start, cursor)
                    if do_test_result: update_record(rowid, "Test Sonuclari Geldi Detay", new_test_result, cursor)

                    if self.cb_update_turu.isChecked(): update_record(rowid, "Ihale Turu", self.turu_edit.currentText(), cursor)
                    if self.cb_update_usulu.isChecked(): update_record(rowid, "Ihale Usulu", self.usulu_edit.currentText(), cursor)
                    if self.cb_update_yak_maliyet.isChecked(): update_record(rowid, "Yak. Maliyet", parse_money(self.yak_maliyet_edit.text()), cursor)
                    try:
                        final_teslim_str = str(r[5])[:10] if len(r) > 5 and r[5] else ""
                        if do_sozlesme:
                            old_sozlesme_str = str(r[17])[:10] if len(r) > 17 and r[17] else ""
                            if old_sozlesme_str:
                                old_soz_dt = datetime.strptime(old_sozlesme_str, "%Y-%m-%d")
                                delta = (new_sozlesme_dt - old_soz_dt).days
                                if delta != 0 and final_teslim_str:
                                    old_tes_dt = datetime.strptime(final_teslim_str, "%Y-%m-%d")
                                    final_teslim_str = (old_tes_dt + timedelta(days=delta)).strftime("%Y-%m-%d")
                        final_start_str = str(r[26])[:10] if len(r) > 26 and r[26] else ""
                        if self.cb_update_ise_baslama.isChecked():
                            final_start_str = self.ise_baslama_edit.date().toString("yyyy-MM-dd")
                        if final_teslim_str and final_start_str:
                            start_dt = datetime.strptime(final_start_str, "%Y-%m-%d")
                            end_dt = datetime.strptime(final_teslim_str, "%Y-%m-%d")
                            calc_dur = (end_dt - start_dt).days + 1
                            old_dur = str(r[27]) if len(r) > 27 and r[27] else ""
                            if old_dur != f"{calc_dur} Gün":
                                update_record(rowid, "Parti Teslim Suresi", f"{calc_dur} Gün", cursor)
                    except Exception:
                        pass
                    if self.cb_update_ihale_tarihi.isChecked(): update_record(rowid, "Ihale Tarihi", self.ihale_tarihi_edit.date().toString("yyyy-MM-dd"), cursor)
                    if self.cb_update_ise_baslama.isChecked(): update_record(rowid, "Ise Baslama Tarihi", self.ise_baslama_edit.date().toString("yyyy-MM-dd"), cursor)
                    if self.cb_update_cari.isChecked(): update_record(rowid, "Cari No", self.cari_edit.text(), cursor)
                    if self.cb_update_proje.isChecked(): update_record(rowid, "Proje No", self.proje_edit.text(), cursor)
                    if self.cb_update_kart.isChecked(): update_record(rowid, "Kart No", self.kart_edit.text(), cursor)
                    if self.cb_update_ambar.isChecked():
                        amb_val = str(self.ambar_edit.currentText())
                        cursor.execute("UPDATE data SET `Teslim Ambari` = ? WHERE rowid = ?", (amb_val, rowid))

                    for state_text, state_val in status_updates.items():
                        db_col = COLUMN_MAPPING.get(state_text, state_text)
                        update_record(rowid, db_col, state_val, cursor)

                    update_record(rowid, "SonGuncelleme", audit_log, cursor)

                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

            ikn_list = sorted(set(str(r[1]) for r in self.records if len(r) > 1 and r[1]))
            firma_list = sorted(set(str(r[2]) for r in self.records if len(r) > 2 and r[2]))
            log_header = (f"IKN: {'; '.join(ikn_list[:3])}" + (f" ...ve {len(ikn_list)-3} daha" if len(ikn_list) > 3 else "")) if ikn_list else ""
            if firma_list:
                log_header += (" | " if log_header else "") + (firma_list[0] if len(firma_list) == 1 else '; '.join(firma_list[:2]) + (f" ...ve {len(firma_list)-2} daha" if len(firma_list) > 2 else ""))
            log_desc = (log_header + " | " if log_header else "") + " | ".join(value_details) + f" | Toplam {len(self.records)} kayıt güncellendi"
            log_action("Toplu Gelişmiş Düzenleme", log_desc)

            QMessageBox.information(self, "Başarılı", f"Seçili {len(self.records)} kayıt başarıyla güncellendi.")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Toplu güncelleme sırasında hata oluştu:\n{e}")

# --- ÖZET SAYFASI ---
# (SummaryWidget aynı, değişmedi)

# --- DETAY
# --- ÖZET SAYFASI ---
class ClickableCard(QFrame):
    def __init__(self, record, parent_summary, mode='full'):
        super().__init__()
        self.record = record
        self.parent_summary = parent_summary
        self.mode = mode
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip("Verileri düzenlemek için çift tıklayın 🛠️" if mode == 'full' else "İşlem adımlarını güncellemek için çift tıklayın ⚡")
        self.setStyleSheet("background: transparent; border: none;")

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            if self.mode == 'full':
                self.parent_summary.open_edit(self.record)
            else:
                self.parent_summary.open_edit(self.record, simplified=True)

    def contextMenuEvent(self, event):
        menu = QtWidgets.QMenu(self)
        menu.setStyleSheet("QMenu { background-color: #f8fafc; color: #1e293b; border: 1px solid #cbd5e1; } QMenu::item { padding: 6px 20px; } QMenu::item:selected { background-color: #6366f1; color: white; }")
        bulk_edit_action = menu.addAction("📦 İhalenin Tüm Parti Verilerini Topluca Düzenle")

        action = menu.exec(event.globalPos())
        if action == bulk_edit_action:
            self.open_bulk_edit_for_tender()

    def open_bulk_edit_for_tender(self):
        # Bu ihaleye ait (aynı IKN ve Firma) tüm kayıtları DB'den çek
        ikn = self.record[1]
        firma = self.record[2]

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT rowid, * FROM data WHERE IKN=? AND `Yuklenici Firma`=?", (ikn, firma))
            all_parts = cursor.fetchall()
            conn.close()

            if all_parts:
                dialog = BulkEditDialog(all_parts, self.parent_summary)
                if dialog.exec():
                    self.parent_summary.refresh_summary()
                    if hasattr(self.parent_summary.parent_window, 'detail_widget'):
                        self.parent_summary.parent_window.detail_widget.refresh_data()
            else:
                QMessageBox.information(self, 'Bilgi', 'Düzenlenecek kayıt bulunamadı.')
        except Exception as e:
            QMessageBox.critical(self, 'Hata', f'Toplu düzenleme başlatılamadı:\n{e}')

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
        btn_clr.setToolTip("Temizle (Alt+X)")
        btn_clr.clicked.connect(self.clear_filters)

        self.btn_show_all = QPushButton("Tümünü Göster")
        self.btn_show_all.setCheckable(True)
        self.btn_show_all.setObjectName("SecondaryBtn") # Başlangıçta gri (pasif)
        self.btn_show_all.setEnabled(False)
        self.btn_show_all.clicked.connect(self.refresh_summary)

        self.search = QLineEdit()
        self.search.setPlaceholderText("🔍")
        self.search.setFixedWidth(140)
        self.search.setMinimumHeight(28)
        self.search.textChanged.connect(self.apply_filters)
        header_layout.addWidget(self.search)

        header_layout.addWidget(QLabel("Sıralama:"))
        header_layout.addWidget(self.cb_sort)
        header_layout.addWidget(QLabel("Firma:"))
        header_layout.addWidget(self.cb_firm)
        header_layout.addWidget(QLabel("İhale:"))
        header_layout.addWidget(self.cb_tender)

        # İşlem Adımı multi-select (radio mantığı: her adımın ✓ ve ✗ seçeneği)
        self.cb_step_model = QStandardItemModel()
        self.cb_step = QComboBox()
        self.cb_step.setEditable(True)
        self.cb_step.lineEdit().setReadOnly(True)
        self.cb_step.lineEdit().setPlaceholderText("İşlem adımı seçin...")
        self.cb_step.setView(QListView())
        self.cb_step.setItemDelegate(DropdownDelegate())
        self.cb_step.setMinimumWidth(220)

        self.step_pairs = [
            ("✓ Ambar Teslimi Gerçekleşti", "✗ Ambar Teslimi Gerçekleşmedi", 7),
            ("✓ Heyet Başkanına Haber Verildi", "✗ Heyet Başkanına Haber Verilmedi", 19),
            ("✓ Testler Başladı", "✗ Testler Başlamadı", 8),
            ("✓ Test Sonuçları Geldi", "✗ Test Sonuçları Gelmedi", 9),
            ("✓ Kabul Raporu imzada", "✗ Kabul Raporu imzada değil", 10),
            ("✓ Kabul Yapıldı", "✗ Kabul Yapılmadı", 11),
            ("✓ Ödeme Belgesi Oluşturuldu", "✗ Ödeme Belgesi Oluşturulmadı", 13)
        ]

        # En üste kontrol butonları
        select_all_item = QStandardItem("Tümünü Seç")
        select_all_item.setCheckable(False)
        select_all_item.setForeground(QColor("#6366f1"))
        font = QFont()
        font.setBold(True)
        select_all_item.setFont(font)
        self.cb_step_model.appendRow(select_all_item)

        deselect_all_item = QStandardItem("Tümünü Seçme")
        deselect_all_item.setCheckable(False)
        deselect_all_item.setForeground(QColor("#ef4444"))
        font2 = QFont()
        font2.setBold(True)
        deselect_all_item.setFont(font2)
        self.cb_step_model.appendRow(deselect_all_item)

        for checked_text, unchecked_text, col_idx in self.step_pairs:
            item_on = QStandardItem(checked_text)
            item_on.setCheckable(True)
            item_on.setCheckState(Qt.CheckState.Unchecked)
            self.cb_step_model.appendRow(item_on)

            item_off = QStandardItem(unchecked_text)
            item_off.setCheckable(True)
            item_off.setCheckState(Qt.CheckState.Unchecked)
            self.cb_step_model.appendRow(item_off)

        self.cb_step.setModel(self.cb_step_model)
        self.cb_step_model.itemChanged.connect(self.on_step_changed)
        self.cb_step.view().viewport().installEventFilter(self)

        header_layout.addWidget(QLabel("İşlem Adımı Filtresi:"))
        header_layout.addWidget(self.cb_step)
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
        self.btn_show_all.setText("Günceli Göster" if show_all else "Tümünü Göster")
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

    def get_step_filters(self):
        filters = {}
        for i in range(self.cb_step_model.rowCount()):
            item = self.cb_step_model.item(i)
            if not item or item.checkState() != Qt.CheckState.Checked:
                continue
            text = item.text()
            for checked_text, unchecked_text, col_idx in self.step_pairs:
                if text == checked_text:
                    filters[col_idx] = True
                elif text == unchecked_text:
                    filters[col_idx] = False
        return filters

    def apply_filters(self):
        step_filters = self.get_step_filters()
        search_text = self.search.text().lower()
        is_filtered = (self.cb_firm.currentIndex() > 0 or self.cb_tender.currentIndex() > 0 or len(step_filters) > 0 or bool(search_text))
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
            if item.widget():
                item.widget().hide()
                item.widget().deleteLater()

        f = self.cb_firm.currentText()
        t = self.cb_tender.currentText()
        s = self.cb_sort.currentText()

        filtered = [r for r in self.all_summary_data if
                    (f == "Tümü" or str(r[2]) == f) and
                    (t == "Tümü" or str(r[3]) == t) and
                    (not search_text or search_text in str(r).lower())]

        if step_filters:
            def matches_step_filters(record):
                for col_idx, required_state in step_filters.items():
                    is_checked = col_idx < len(record) and _is_checked(record[col_idx])
                    if is_checked != required_state:
                        return False
                return True
            filtered = [r for r in filtered if matches_step_filters(r)]

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

    def on_step_changed(self):
        # Radio mantığı: her çiftten sadece biri seçili kalabilir
        self.cb_step_model.blockSignals(True)
        for checked_text, unchecked_text, _ in self.step_pairs:
            on_checked = False
            off_checked = False
            for i in range(self.cb_step_model.rowCount()):
                item = self.cb_step_model.item(i)
                if item:
                    if item.text() == checked_text and item.checkState() == Qt.CheckState.Checked:
                        on_checked = True
                    elif item.text() == unchecked_text and item.checkState() == Qt.CheckState.Checked:
                        off_checked = True
            if on_checked and off_checked:
                for i in range(self.cb_step_model.rowCount()):
                    item = self.cb_step_model.item(i)
                    if item and item.text() == unchecked_text and item.checkState() == Qt.CheckState.Checked:
                        item.setCheckState(Qt.CheckState.Unchecked)
        self.cb_step_model.blockSignals(False)

        step_filters = self.get_step_filters()
        display_parts = []
        for col_idx, state in step_filters.items():
            for checked_text, unchecked_text, ci in self.step_pairs:
                if ci == col_idx:
                    display_parts.append(checked_text if state else unchecked_text)
                    break
        display_text = ", ".join(display_parts) if display_parts else "Tümü"
        self.cb_step.lineEdit().setText(display_text)
        self.cb_step.setToolTip(display_text)
        self.apply_filters()

    def step_select_all(self):
        self.cb_step_model.blockSignals(True)
        for i in range(self.cb_step_model.rowCount()):
            item = self.cb_step_model.item(i)
            if item and item.isCheckable():
                text = item.text()
                for checked_text, _, _ in self.step_pairs:
                    if text == checked_text:
                        item.setCheckState(Qt.CheckState.Checked)
                        break
                else:
                    item.setCheckState(Qt.CheckState.Unchecked)
        self.cb_step_model.blockSignals(False)
        self.on_step_changed()

    def step_deselect_all(self):
        self.cb_step_model.blockSignals(True)
        for i in range(self.cb_step_model.rowCount()):
            item = self.cb_step_model.item(i)
            if item and item.isCheckable():
                item.setCheckState(Qt.CheckState.Unchecked)
        self.cb_step_model.blockSignals(False)
        self.on_step_changed()

    def clear_filters(self):
        self.cb_firm.setCurrentIndex(0)
        self.cb_tender.setCurrentIndex(0)
        self.step_deselect_all()
        self.cb_sort.setCurrentIndex(0)
        self.search.clear()
        self.apply_filters()

    def eventFilter(self, obj, event):
        if obj == self.cb_step.view().viewport() and event.type() == QEvent.Type.MouseButtonRelease:
            index = self.cb_step.view().indexAt(event.position().toPoint())
            item = self.cb_step_model.itemFromIndex(index)
            if item:
                text = item.text()
                if text == "Tümünü Seç":
                    self.step_select_all()
                elif text == "Tümünü Seçme":
                    self.step_deselect_all()
                else:
                    item.setCheckState(Qt.CheckState.Unchecked if item.checkState() == Qt.CheckState.Checked else Qt.CheckState.Checked)
            return True
        return super().eventFilter(obj, event)

    def create_card(self, record):
        is_completed = (len(record) > 11 and _is_checked(record[11]))
        date_color = get_date_color(record[5], is_completed) if len(record) > 5 else None

        bg_color = "white"
        border_color = date_color if date_color else ("#e2e8f0")
        text_color = "#1e293b"
        sub_text_color = "#64748b"

        main_card = QFrame()
        main_card.setObjectName("Card")
        main_card.setStyleSheet(f"""
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

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setXOffset(0)
        shadow.setYOffset(4)
        shadow.setColor(QColor(0, 0, 0, 20))
        main_card.setGraphicsEffect(shadow)

        main_layout = QVBoxLayout(main_card)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # --- ÜST KISIM (Tam Düzenleme) ---
        top_widget = ClickableCard(record, self, mode='full')
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(15, 15, 15, 5)
        top_layout.setSpacing(10)

        h_head = QHBoxLayout()
        ikn_lbl = QLabel(f" IKN: {record[1]} ") if len(record) > 1 else QLabel(" IKN: - ")
        ikn_bg_color = "#f1f5f9"
        ikn_style = f"background-color: {ikn_bg_color}; border-radius: 4px; padding: 2px;"
        ikn_lbl.setStyleSheet(f"font-weight: bold; color: {'#6366f1'}; font-size: 16px; {ikn_style}")
        h_head.addWidget(ikn_lbl)

        # Sözleşme Tarihi bilgisini ekle
        sozlesme_raw = str(record[17])[:10] if len(record) > 17 and record[17] else "-"
        soz_tarih_tr = format_date_tr(sozlesme_raw) if sozlesme_raw != "-" else "-"
        sozlesme_lbl = QLabel(f" 📝 Sözl. Tarihi: {soz_tarih_tr} ")
        sozlesme_lbl.setStyleSheet(f"font-weight: bold; color: {sub_text_color}; font-size: 13px; {ikn_style}")
        h_head.addSpacing(5)
        h_head.addWidget(sozlesme_lbl)

        if date_color:
            status_tag = QLabel("⚠️ KABUL İŞLEMİ TAMAMLANMADI" if date_color == "#ef4444" else "⏳ TESLİM SÜRESİ YAKLAŞIYOR")
            status_tag.setStyleSheet(f"color: white; background-color: {date_color}; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;")
            h_head.addWidget(status_tag)

        h_head.addStretch()
        top_layout.addLayout(h_head)

        title_lbl = QLabel(str(record[3]) if len(record) > 3 else "")
        title_lbl.setWordWrap(True)
        title_bg_color = "#f8fafc"
        title_style = f"background-color: {title_bg_color}; border-radius: 6px; padding: 5px;"
        title_lbl.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {text_color}; {title_style}")
        top_layout.addWidget(title_lbl)

        info_layout = QHBoxLayout()
        firma_lbl = QLabel(f"🏢 {record[2]}") if len(record) > 2 else QLabel("🏢 -")
        miktar_val = str(record[16]) if len(record) > 16 and record[16] else "-"
        miktar_lbl = QLabel(f"🔢 Miktar: {miktar_val}")
        tutar_lbl = QLabel(f"💰 {display_money(record[6])}") if len(record) > 6 else QLabel("💰 0,00")
        parti_lbl = QLabel(f"📦 Parti: {record[4]}") if len(record) > 4 else QLabel("📦 -")
        tarih_val = format_date_tr(record[5]) if len(record) > 5 and record[5] else "-"
        tarih_lbl = QLabel(f"📅 {tarih_val}")

        # Parti Teslim Süresi Hesapla
        dur_str = "-"
        if record[5] and len(record) > 26 and record[26]:
            try:
                d1 = datetime.strptime(str(record[26])[:10], "%Y-%m-%d")
                d2 = datetime.strptime(str(record[5])[:10], "%Y-%m-%d")
                diff = (d2 - d1).days + 1
                if diff > 0: dur_str = f"{diff} Gün"
            except: pass
        duration_lbl = QLabel(f"⏱️ Süre: {dur_str}")

        amb_val = str(record[34]) if len(record) > 34 and record[34] else "-"
        amb_lbl = QLabel(f"🏭 Ambar: {amb_val}")

        for lbl in [firma_lbl, miktar_lbl, tutar_lbl, parti_lbl, tarih_lbl, duration_lbl, amb_lbl]:
            lbl_bg_color = "#f1f5f9"
            lbl_style = f"background-color: {lbl_bg_color}; border-radius: 4px; padding: 3px 8px;"
            lbl.setStyleSheet(f"color: {sub_text_color}; font-size: 14px; {lbl_style}")
            info_layout.addWidget(lbl)
            if lbl != amb_lbl:
                info_layout.addSpacing(10)

        info_layout.addStretch()
        top_layout.addLayout(info_layout)
        main_layout.addWidget(top_widget)

        # --- ALT KISIM (Hızlı Durum Güncelleme) ---
        bottom_widget = ClickableCard(record, self, mode='quick')
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(15, 5, 15, 15)
        bottom_layout.setSpacing(5)

        status_box = QFrame()
        status_box.setStyleSheet(f"background-color: {'white'}; border-radius: 8px; padding: 10px;")
        status_layout = QVBoxLayout(status_box)

        row_steps = QHBoxLayout()
        row_steps.setSpacing(15)

        steps = [("Ambar Teslimi Gerçekleşti", 7), ("Heyet Başkanına Haber Verildi", 19),
                 ("Testler Başladı", 8), ("Test Sonuçları Geldi", 9),
                 ("Kabul Raporu imzada", 10), ("Kabul Yapıldı", 11), ("Ödeme Belgesi Oluşturuldu", 13)]

        for text, idx in steps:
            is_checked = (idx < len(record) and _is_checked(record[idx]))

            # Detay bilgisini ekle
            display_text = text
            if text == "Testler Başladı":
                # Index 20
                detay = str(record[20]) if len(record) > 20 and record[20] else ""
                if detay: display_text += f" ({detay})"
            elif text == "Test Sonuçları Geldi":
                # Index 21
                detay = str(record[21]) if len(record) > 21 and record[21] else ""
                if detay: display_text += f" ({detay})"

            dot = "●"
            lbl = QLabel(f"{dot} {display_text}")
            color = ("#16a34a") if is_checked else ("#64748b")
            lbl.setStyleSheet(f"font-size: 12px; font-weight: bold; color: {color};")
            row_steps.addWidget(lbl)

        row_steps.addStretch()
        status_layout.addLayout(row_steps)

        desc = record[14] if len(record) > 14 and record[14] else ""
        if desc:
            d_lbl = QLabel(f"📝 {desc}")
            d_color = "#475569"
            d_border = "#e2e8f0"
            d_lbl.setStyleSheet(f"color: {d_color}; font-size: 14px; border-top: 1px solid {d_border}; margin-top: 5px; padding-top: 5px;")
            status_layout.addWidget(d_lbl)

        bottom_layout.addWidget(status_box)

        last_upd_val = str(record[15]) if len(record) > 15 and record[15] else ""
        if last_upd_val:
            upd_lbl = QLabel(f"ℹ️ {last_upd_val}")
            upd_color = "#64748b"
            upd_lbl.setStyleSheet(f"color: {upd_color}; font-size: 11px; margin-top: 2px;")
            upd_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
            bottom_layout.addWidget(upd_lbl)

        main_layout.addWidget(bottom_widget)
        return main_card

    def open_edit(self, record, simplified=False):
        if EditDialog(record, self, simplified=simplified).exec():
            self.refresh_summary()
            if self.parent_window: self.parent_window.refresh_all()

# --- İHALE DETAYLARI SEKME ---
class TenderWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.current_status_filter = "active" # all, active, completed
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

        btn_layout.addSpacing(10)
        self.btn_export = QPushButton("📊 Verileri CSV Olarak Dışa Aktar")
        self.btn_export.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_export.setObjectName("InfoBtn")
        self.btn_export.clicked.connect(self.export_to_csv)
        btn_layout.addWidget(self.btn_export)

        btn_layout.addStretch()

        self.total_label = QLabel("<b>GENEL TOPLAM: 0,00 TL</b>")
        lbl_bg = "#f1f5f9"
        self.total_label.setStyleSheet(f"font-size: 14px; color: #6366f1; background-color: {lbl_bg}; padding: 5px 12px; border-radius: 6px; border: 1px solid #6366f1;")
        btn_layout.addWidget(self.total_label)

        btn_layout.addSpacing(10)

        self.remaining_total_label = QLabel("<b>KALAN TOPLAM: 0,00 TL</b>")
        self.remaining_total_label.setStyleSheet(f"font-size: 14px; color: #ef4444; background-color: {lbl_bg}; padding: 5px 12px; border-radius: 6px; border: 1px solid #ef4444;")
        btn_layout.addWidget(self.remaining_total_label)

        layout.addLayout(btn_layout)

        self.btn_active.setChecked(True)
        self.btn_all.clicked.connect(lambda: self.set_status_filter("all"))
        self.btn_active.clicked.connect(lambda: self.set_status_filter("active"))
        self.btn_completed.clicked.connect(lambda: self.set_status_filter("completed"))

        layout.addSpacing(10)

        # --- ARAMA PANELİ ---
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("🔍 Ara:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("İKN, Firma veya İhale Adı ile ara...")
        self.search_edit.textChanged.connect(self.refresh_data)
        search_layout.addWidget(self.search_edit, stretch=1)

        btn_clear = QPushButton("Temizle")
        btn_clear.setToolTip("Temizle (Alt+X)")
        btn_clear.clicked.connect(self.clear_search)
        search_layout.addWidget(btn_clear)

        layout.addLayout(search_layout)
        layout.addSpacing(10)

        # Splitter creates a resizable divider between two tables
        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter)

        # --- TOP PANEL: TENDER LIST ---
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 10)

        title_lbl = QLabel("📁 Sözleşme Listesi (Detayları görmek için bir satır seçin)")
        title_lbl.setStyleSheet("font-size: 14px; font-weight: bold; color: #5e35b1;")
        top_layout.addWidget(title_lbl)

        self.tender_table = QTableWidget()
        self.tender_table.setAlternatingRowColors(True)
        self.tender_table.setColumnCount(12)
        self.tender_table.setHorizontalHeaderLabels([
            "IKN", "Firma", "İhale Adı",
            "İhale Tarihi", "Sözleşme Tarihi", "İşe Başlama", "Parti Teslim Süresi", "İş Sonu",
            "Yak. Maliyet", "Sözleşme Tutarı", "Toplam Parti", "Kalan Parti"
        ])
        self.tender_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tender_table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.tender_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tender_table.itemSelectionChanged.connect(self.on_tender_selected)
        self.tender_table.setWordWrap(True)
        self.tender_table.setVerticalScrollMode(QtWidgets.QAbstractItemView.ScrollMode.ScrollPerPixel)

        # Sağ tık menüsü ayarları
        self.tender_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tender_table.customContextMenuRequested.connect(self.show_tender_context_menu)

        # Başlangıç Boyutlandırma
        self.tender_table.resizeColumnsToContents()

        # Firma sütununu (index 1) mevcut halinin 4 katı yap
        firm_w = self.tender_table.columnWidth(1)
        self.tender_table.setColumnWidth(1, firm_w * 4)

        # IKN sütununun (index 0) tam göründüğünden emin ol
        if self.tender_table.columnWidth(0) < 120:
            self.tender_table.setColumnWidth(0, 120)

        header = self.tender_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive) # Sürükleyerek boyutlandırmaya izin ver
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Interactive)
        self.tender_table.setColumnWidth(6, 100)

        # Sadece Firma (1) ve İhale Adı (2) sütunları kaydırılsın
        self.tender_table.setItemDelegate(WordWrapDelegate([1, 2], self.tender_table))

        self.tender_table.setSortingEnabled(True) # Başlıklara tıklayarak sıralamayı aç

        top_layout.addWidget(self.tender_table)
        splitter.addWidget(top_widget)

        # --- BOTTOM PANEL: PART DETAILS ---
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 10, 0, 0)

        detail_lbl = QLabel("📦 Seçili Sözleşmenin Parti Bilgileri")
        detail_lbl.setStyleSheet("font-size: 14px; font-weight: bold; color: #5e35b1;")

        h_detail = QHBoxLayout()
        h_detail.addWidget(detail_lbl)
        h_detail.addStretch()
        self.detail_total_label = QLabel("<b>Seçili Sözleşmede Bekleyen Alacak: 0,00 TL</b>")
        lbl_bg = "#f1f5f9"
        self.detail_total_label.setStyleSheet(f"font-size: 13px; color: #ef4444; background-color: {lbl_bg}; padding: 4px 10px; border-radius: 4px; border: 1px solid #ef4444;")
        h_detail.addWidget(self.detail_total_label)
        bottom_layout.addLayout(h_detail)

        self.part_table = QTableWidget()
        self.part_table.setAlternatingRowColors(True)
        self.part_table.setColumnCount(6)
        self.part_table.setHorizontalHeaderLabels(["Parti No", "Teslim Tarihi", "Miktar", "Tutar", "Durum", "Açıklama"])
        self.part_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        header_part = self.part_table.horizontalHeader()
        header_part.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.part_table.setColumnWidth(0, 80)
        self.part_table.setColumnWidth(1, 100)
        self.part_table.setColumnWidth(2, 100)
        self.part_table.setColumnWidth(3, 120)
        self.part_table.setColumnWidth(4, 100)
        self.part_table.setColumnWidth(5, 250)
        self.part_table.setSortingEnabled(True)

        bottom_layout.addWidget(self.part_table)
        splitter.addWidget(bottom_widget)

        # Initial sizing
        splitter.setSizes([300, 300])

        self.refresh_data()

    def show_tender_context_menu(self, pos):
        """İhale listesi için sağ tık menüsü."""
        selected_ranges = self.tender_table.selectedRanges()
        if not selected_ranges:
            return

        menu = QtWidgets.QMenu(self)
        bulk_edit_action = menu.addAction("📦 Seçili İhaleleri Topluca Düzenle")

        action = menu.exec(self.tender_table.viewport().mapToGlobal(pos))
        if action == bulk_edit_action:
            self.run_bulk_edit_for_selected_tenders()

    def run_bulk_edit_for_selected_tenders(self):
        """Seçilen ihalelere ait tüm partileri toplu düzenleme penceresinde açar."""
        selected_rows = set()
        for r in self.tender_table.selectedRanges():
            for row in range(r.topRow(), r.bottomRow() + 1):
                selected_rows.add(row)

        if not selected_rows:
            return

        all_records_to_edit = []
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            for row in selected_rows:
                item_ikn = self.tender_table.item(row, 0)
                item_firma = self.tender_table.item(row, 1)
                if item_ikn is None or item_firma is None:
                    continue
                ikn = item_ikn.text()
                firma = item_firma.text()

                # Bu ihaleye ait tüm partileri çek
                cursor.execute("SELECT rowid, * FROM data WHERE IKN=? AND `Yuklenici Firma`=?", (ikn, firma))
                all_records_to_edit.extend(cursor.fetchall())

            conn.close()

            if all_records_to_edit:
                dialog = BulkEditDialog(all_records_to_edit, self)
                if dialog.exec():
                    self.refresh_data()
                    if hasattr(self.parent_window, 'detail_widget'):
                        self.parent_window.detail_widget.refresh_data()
                    if hasattr(self.parent_window, 'summary_widget'):
                        self.parent_window.summary_widget.refresh_summary()
            else:
                QMessageBox.information(self, "Bilgi", "Düzenlenecek kayıt bulunamadı.")

        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Toplu düzenleme başlatılamadı:\n{e}")

    def set_status_filter(self, mode):
        self.current_status_filter = mode
        self.btn_all.setChecked(mode == "all")
        self.btn_active.setChecked(mode == "active")
        self.btn_completed.setChecked(mode == "completed")
        self.refresh_data()

    def export_to_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Verileri CSV Olarak Kaydet", "", "CSV Dosyası (*.csv)")
        if not path:
            return

        try:
            with open(path, mode='w', encoding='utf-8-sig', newline='') as file:
                writer = csv.writer(file, delimiter=';')

                # --- SECTION 1: İHALE LİSTESİ ---
                writer.writerow(["İHALE LİSTESİ"])
                headers = [self.tender_table.horizontalHeaderItem(i).text() for i in range(self.tender_table.columnCount())]
                writer.writerow(headers)

                for row in range(self.tender_table.rowCount()):
                    row_data = [self.tender_table.item(row, col).text() if self.tender_table.item(row, col) else ""
                                for col in range(self.tender_table.columnCount())]
                    writer.writerow(row_data)

                # --- SECTION 2: SEÇİLİ İHALE DETAYLARI ---
                row = self.tender_table.currentRow()
                if row >= 0:
                    writer.writerow([]) # Boş satır
                    writer.writerow(["SEÇİLİ İHALE DETAYLARI"])
                    tender_ikn = self.tender_table.item(row, 0).text() if self.tender_table.item(row, 0) else ""
                    tender_name = self.tender_table.item(row, 2).text() if self.tender_table.item(row, 2) else ""
                    writer.writerow([f"İhale: {tender_name} (IKN: {tender_ikn})"])

                    part_headers = [self.part_table.horizontalHeaderItem(i).text() for i in range(self.part_table.columnCount())]
                    writer.writerow(part_headers)

                    for r in range(self.part_table.rowCount()):
                        r_data = [self.part_table.item(r, c).text() if self.part_table.item(r, c) else ""
                                  for c in range(self.part_table.columnCount())]
                        writer.writerow(r_data)
            QMessageBox.information(self, "Başarılı", f"Veriler başarıyla dışa aktarıldı:\n{path}")
            log_action("CSV Dışa Aktar (İhale Detayları)", f"Dosya: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"CSV dışa aktarma hatası:\n{e}")

    def clear_search(self):
        self.search_edit.clear()

    def refresh_data(self):
        self.tender_table.blockSignals(True)
        all_data = get_aggregated_tender_data()
        count_all = 0
        count_active = 0
        count_completed = 0

        filtered_data = []
        for item in all_data:
            # Check completion status of the TENDER (all parts must be completed)
            is_tender_completed = True
            for part in item["parts"]:
                # part[13] is 'Odeme Emri Hazirlandi'
                if not (len(part) > 13 and _is_checked(part[13])):
                    is_tender_completed = False
                    break

            # Update Stats
            count_all += 1
            if is_tender_completed:
                count_completed += 1
            else:
                count_active += 1

            # Filter Logic
            status_match = False
            if self.current_status_filter == "all":
                status_match = True
            elif self.current_status_filter == "active" and not is_tender_completed:
                status_match = True
            elif self.current_status_filter == "completed" and is_tender_completed:
                status_match = True

            if status_match:
                # Metin Filtreleme
                search_txt = self.search_edit.text().lower()
                if not search_txt:
                    filtered_data.append(item)
                else:
                    ikn = str(item.get("ikn", "")).lower()
                    firma = str(item.get("firma", "")).lower()
                    ihale = str(item.get("ihale", "")).lower()
                    if search_txt in ikn or search_txt in firma or search_txt in ihale:
                        filtered_data.append(item)

        # Update Button Texts
        self.btn_all.setText(f"Tüm İşler ({count_all})")
        self.btn_active.setText(f"Devam Edenler ({count_active})")
        self.btn_completed.setText(f"Tamamlananlar ({count_completed})")

        # Update Grand Total
        grand_total = sum(item["total_amount"] for item in filtered_data)
        self.total_label.setText(f"<b>GENEL TOPLAM: {display_money(grand_total)}</b>")

        # Update Remaining Total (Unpaid parts where index 13 is not 1.0)
        remaining_total = 0.0
        for item in filtered_data:
            for part in item["parts"]:
                # part[13] is 'Odeme Emri Hazirlandi'
                if not (len(part) > 13 and _is_checked(part[13])):
                    remaining_total += float(part[6] or 0.0)
        self.remaining_total_label.setText(f"<b>KALAN TOPLAM: {display_money(remaining_total)}</b>")

        self.tender_table.setRowCount(len(filtered_data))
        self.tender_table.setSortingEnabled(False)

        for i, item in enumerate(filtered_data):
            # Column 0: IKN (Store full data in UserRole + 1)
            ikn_item = SortableTableWidgetItem(str(item["ikn"]))
            ikn_item.setData(Qt.ItemDataRole.UserRole + 1, item)
            self.tender_table.setItem(i, 0, ikn_item)

            # Column 1: Firma
            self.tender_table.setItem(i, 1, SortableTableWidgetItem(str(item["firma"])))

            # Column 2: Ihale Adi - Sortable
            self.tender_table.setItem(i, 2, SortableTableWidgetItem(str(item["ihale"])))

            # Column 3: İhale Tarihi
            parts = item["parts"]
            ihale_tarihi_raw = str(parts[0][25])[:10] if len(parts[0]) > 25 and parts[0][25] else ""
            ihale_tarihi_item = SortableTableWidgetItem(format_date_tr(ihale_tarihi_raw))
            ihale_tarihi_item.setData(Qt.ItemDataRole.UserRole, ihale_tarihi_raw if ihale_tarihi_raw else "0000-00-00")
            ihale_tarihi_item.setTextAlignment(Qt.AlignCenter)
            self.tender_table.setItem(i, 3, ihale_tarihi_item)

            # Column 4: Sözleşme Tarihi
            sozlesme_raw = parts[0][17] if len(parts[0]) > 17 else ""
            sozlesme_item = SortableTableWidgetItem(format_date_tr(sozlesme_raw))
            sozlesme_item.setData(Qt.ItemDataRole.UserRole, sozlesme_raw if sozlesme_raw else "0000-00-00")
            sozlesme_item.setTextAlignment(Qt.AlignCenter)
            self.tender_table.setItem(i, 4, sozlesme_item)

            # Column 5: İşe Başlama (Formatlanmış ve Saat Bilgisi Arındırılmış)
            ise_baslama_raw = str(parts[0][26])[:10] if len(parts[0]) > 26 and parts[0][26] else ""
            ise_item = SortableTableWidgetItem(format_date_tr(ise_baslama_raw))
            ise_item.setData(Qt.ItemDataRole.UserRole, ise_baslama_raw if ise_baslama_raw else "0000-00-00")
            ise_item.setTextAlignment(Qt.AlignCenter)
            self.tender_table.setItem(i, 5, ise_item)

            # Column 6: Parti Teslim Süresi
            delivery_dates = [p[5] for p in parts if p[5]]
            is_sonu_raw = max(delivery_dates) if delivery_dates else ""
            parti_teslim_suresi_text = "-"
            parti_teslim_suresi_days = -1
            if sozlesme_raw and is_sonu_raw:
                try:
                    d1 = datetime.strptime(str(ise_baslama_raw if ise_baslama_raw else sozlesme_raw)[:10], "%Y-%m-%d")
                    d2 = datetime.strptime(str(is_sonu_raw)[:10], "%Y-%m-%d")
                    diff = (d2 - d1).days + 1
                    parti_teslim_suresi_days = diff
                    parti_teslim_suresi_text = f"{diff} Gün"
                except: pass

            # Column 7: İş Sonu (Son Parti Teslim Tarihi)
            is_sonu_item = SortableTableWidgetItem(format_date_tr(is_sonu_raw))
            is_sonu_item.setData(Qt.ItemDataRole.UserRole, is_sonu_raw if is_sonu_raw else "0000-00-00")
            is_sonu_item.setTextAlignment(Qt.AlignCenter)
            self.tender_table.setItem(i, 7, is_sonu_item)

            suresi_item = SortableTableWidgetItem(parti_teslim_suresi_text)
            suresi_item.setData(Qt.ItemDataRole.UserRole, parti_teslim_suresi_days)
            suresi_item.setTextAlignment(Qt.AlignCenter)
            self.tender_table.setItem(i, 6, suresi_item)

            # Column 8: Yak. Maliyet - Sortable Numeric
            yak_val_raw = parts[0][24] if len(parts[0]) > 24 and parts[0][24] else 0.0
            try:
                if isinstance(yak_val_raw, str):
                    yak_val_num = float(yak_val_raw.replace(".", "").replace(",", "."))
                else: yak_val_num = float(yak_val_raw)
            except: yak_val_num = 0.0

            yak_item = SortableTableWidgetItem(f"{display_money(yak_val_num)}")
            yak_item.setData(Qt.ItemDataRole.UserRole, yak_val_num)
            yak_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.tender_table.setItem(i, 8, yak_item)

            # Column 9: Sözleşme Tutarı - Sortable Numeric
            tutar_item = SortableTableWidgetItem(display_money(item["total_amount"]))
            tutar_item.setData(Qt.ItemDataRole.UserRole, item["total_amount"])
            tutar_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.tender_table.setItem(i, 9, tutar_item)

            # Column 10: Toplam Parti Sayisi
            part_count = len(item["parts"])
            p_item = SortableTableWidgetItem(format_number(part_count))
            p_item.setData(Qt.ItemDataRole.UserRole, part_count)
            p_item.setTextAlignment(Qt.AlignCenter)
            self.tender_table.setItem(i, 10, p_item)

            # Column 11: Kalan Parti Sayisi
            t_completed = 0
            for p in item["parts"]:
                if len(p) > 13 and _is_checked(p[13]): t_completed += 1
            remaining = part_count - t_completed
            rem_item = SortableTableWidgetItem(format_number(remaining))
            rem_item.setData(Qt.ItemDataRole.UserRole, remaining)
            rem_item.setTextAlignment(Qt.AlignCenter)
            if remaining > 0:
                rem_item.setForeground(QColor("#ef4444"))
                rem_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            else:
                rem_item.setForeground(QColor("#16a34a"))
            self.tender_table.setItem(i, 11, rem_item)

        self.tender_table.resizeRowsToContents()
        # Satır yüksekliklerini maksimum 2 satır (60px) olacak şekilde sınırla
        for i in range(self.tender_table.rowCount()):
            if self.tender_table.rowHeight(i) > 60:
                self.tender_table.setRowHeight(i, 60)
        self.tender_table.setSortingEnabled(True)
        self.tender_table.blockSignals(False)

        # Clear detail view if selection lost/reset or if the selected item is filtered out
        if not self.tender_table.selectedItems():
            self.part_table.setRowCount(0)
            self.detail_total_label.setText("<b>Seçili Sözleşmede Bekleyen Alacak: 0,00 TL</b>")

    def on_tender_selected(self):
        row = self.tender_table.currentRow()
        if row < 0:
            return

        item = self.tender_table.item(row, 0)
        if item is None:
            return
        data = item.data(Qt.ItemDataRole.UserRole + 1)
        if not data:
            return

        parts = data["parts"]

        # Calculate selected tender's remaining balance (Unpaid parts where index 13 is not 1.0)
        selected_remaining = 0.0
        for p in parts:
            if not (len(p) > 13 and _is_checked(p[13])):
                selected_remaining += float(p[6] or 0.0)
        self.detail_total_label.setText(f"<b>Seçili Sözleşmede Bekleyen Alacak: {display_money(selected_remaining)}</b>")

        # Sort by Parti No (index 4) safely
        parts.sort(key=lambda x: int(x[4]) if str(x[4]).isdigit() else 0)

        self.part_table.setSortingEnabled(False)
        self.part_table.setRowCount(len(parts))
        for i, p in enumerate(parts):
            # p structure indexes: 4=PartiNo, 5=Tarih, 6=Tutar, 11=Kabul, 14=Aciklama

            # Parti No
            p_no_val = int(p[4]) if str(p[4]).isdigit() else 0
            p_no_item = SortableTableWidgetItem(str(p[4]))
            p_no_item.setData(Qt.ItemDataRole.UserRole, p_no_val)
            p_no_item.setTextAlignment(Qt.AlignCenter)
            self.part_table.setItem(i, 0, p_no_item)

            # Tarih
            tarih_raw = str(p[5])
            tarih_str = format_date_tr(tarih_raw)
            tarih_item = SortableTableWidgetItem(tarih_str)
            tarih_item.setData(Qt.ItemDataRole.UserRole, tarih_raw if tarih_raw else "0000-00-00")
            tarih_item.setTextAlignment(Qt.AlignCenter)
            self.part_table.setItem(i, 1, tarih_item)

            # Miktar
            miktar_val_str = str(p[16]) if len(p) > 16 and p[16] else ""
            try:
                # Sayısal sıralama için virgüllü formatı temizle
                miktar_num = float(miktar_val_str.replace(".", "").replace(",", "."))
            except: miktar_num = 0.0
            m_item = SortableTableWidgetItem(format_number(miktar_val_str))
            m_item.setData(Qt.ItemDataRole.UserRole, miktar_num)
            m_item.setTextAlignment(Qt.AlignCenter)
            self.part_table.setItem(i, 2, m_item)

            # Tutar
            tutar_val = float(p[6]) if p[6] else 0.0
            tutar_str = display_money(tutar_val)
            tutar_item = SortableTableWidgetItem(tutar_str)
            tutar_item.setData(Qt.ItemDataRole.UserRole, tutar_val)
            tutar_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.part_table.setItem(i, 3, tutar_item)

            # Durum
            status = "Bekliyor"
            if len(p) > 13 and _is_checked(p[13]):
                status = "Tamamlandı"

            status_item = SortableTableWidgetItem(status)
            if status == "Tamamlandı":
                status_item.setForeground(QColor("#16a34a"))
                status_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.part_table.setItem(i, 4, status_item)

            # Açıklama
            desc = str(p[14]) if len(p) > 14 and p[14] else ""
            self.part_table.setItem(i, 5, SortableTableWidgetItem(desc))

        self.part_table.setSortingEnabled(True)

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
        self.btn_clear.setToolTip("Temizle (Alt+X)")
        self.btn_clear.clicked.connect(self.clear_filters)
        filter_layout.addWidget(self.btn_clear)

        filter_layout.addSpacing(10)
        self.btn_export = QPushButton("📊 Verileri CSV Olarak Dışa Aktar")
        self.btn_export.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_export.setObjectName("InfoBtn")
        self.btn_export.clicked.connect(self.export_to_csv)
        filter_layout.addWidget(self.btn_export)

        filter_layout.addSpacing(5)
        self.btn_export_all = QPushButton("📋 Tüm İhale (Sözleşme) Bilgilerini CSV Olarak Kaydet")
        self.btn_export_all.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_export_all.setObjectName("InfoBtn")
        self.btn_export_all.clicked.connect(self.export_all_tenders_to_csv)
        filter_layout.addWidget(self.btn_export_all)

        filter_layout.addStretch()

        self.total_label = QLabel("<b>GENEL TOPLAM: 0,00 TL</b>")
        lbl_bg = "#f1f5f9"
        self.total_label.setStyleSheet(f"font-size: 14px; color: #6366f1; background-color: {lbl_bg}; padding: 5px 12px; border-radius: 6px; border: 1px solid #6366f1;")
        filter_layout.addWidget(self.total_label)

        layout.addLayout(filter_layout)

        # Bilgi baloncuğu
        info_lbl = QLabel("💡 Firma detaylarını görüntülemek için satıra <b>çift tıklayın</b>.")
        info_lbl.setStyleSheet(
            "background-color: #e0f2fe; color: #0369a1; font-size: 12px; "
            "padding: 6px 12px; border-radius: 6px; border: 1px solid #7dd3fc;"
        )
        info_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(info_lbl)

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

        self.table.itemDoubleClicked.connect(self.on_row_double_clicked)

        layout.addWidget(self.table)
        self.refresh_data()

    def on_row_double_clicked(self, item):
        row = item.row()
        firm_name = self.table.item(row, 0).text()
        selected_year = self.cb_year.currentText()

        all_tenders = get_aggregated_tender_data()
        firm_tenders = [t for t in all_tenders if t["firma"] == firm_name]

        # Yıl filtresi uygula
        if selected_year and selected_year != "Tümü":
            filtered = []
            for t in firm_tenders:
                for p in t["parts"]:
                    tarih = str(p[5])[:4] if p[5] else ""
                    if tarih == selected_year:
                        filtered.append(t)
                        break
            firm_tenders = filtered

        if firm_tenders:
            dialog = FirmDetailDialog(firm_name, firm_tenders, self)
            dialog.exec()
        else:
            QMessageBox.information(self, "Bilgi", "Bu firmaya ait ihale kaydı bulunamadı.")

    def export_to_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Verileri CSV Olarak Kaydet", "", "CSV Dosyası (*.csv)")
        if not path:
            return

        try:
            headers = [self.table.horizontalHeaderItem(i).text() for i in range(self.table.columnCount())]

            with open(path, mode='w', encoding='utf-8-sig', newline='') as file:
                writer = csv.writer(file, delimiter=';')
                writer.writerow(headers)

                for row in range(self.table.rowCount()):
                    row_data = [self.table.item(row, col).text() if self.table.item(row, col) else ""
                                for col in range(self.table.columnCount())]
                    writer.writerow(row_data)

            QMessageBox.information(self, "Başarılı", f"Veriler başarıyla dışa aktarıldı:\n{path}")
            log_action("CSV Dışa Aktar (Firma Özetleri)", f"Dosya: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"CSV dışa aktarma hatası:\n{e}")

    def export_all_tenders_to_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Tüm İhale Bilgilerini CSV Olarak Kaydet", "tum_ihale_bilgileri.csv", "CSV Dosyası (*.csv)")
        if not path:
            return
        try:
            all_tenders = get_aggregated_tender_data()
            with open(path, mode='w', encoding='utf-8-sig', newline='') as file:
                writer = csv.writer(file, delimiter=';')
                writer.writerow([
                    "IKN", "Yüklenici Firma", "İhale Adı", "Sözleşme Tutarı",
                    "Toplam Parti Sayısı", "Sözleşme Tarihi", "İhale Türü",
                    "İhale Usulü", "Yak. Maliyet", "İhale Tarihi",
                    "İşe Başlama Tarihi", "Parti Teslim Süresi", "İşin Bitiş (Son parti teslim) Tarihi"
                ])
                for t in all_tenders:
                    parts = t["parts"]
                    p0 = parts[0] if parts else []
                    sozlesme_tarihi = p0[17] if len(p0) > 17 else ""
                    ihale_turu = p0[22] if len(p0) > 22 else ""
                    ihale_usulu = p0[23] if len(p0) > 23 else ""
                    yak_raw = p0[24] if len(p0) > 24 and p0[24] else 0
                    try:
                        yak_num = float(yak_raw) if not isinstance(yak_raw, (int, float)) else float(yak_raw)
                    except:
                        yak_num = 0.0
                    yak_maliyet = display_money(yak_num)
                    ihale_tarihi = p0[25] if len(p0) > 25 else ""
                    ise_baslama = p0[26] if len(p0) > 26 else ""
                    parti_teslim_suresi = p0[27] if len(p0) > 27 else ""
                    teslim_tarihleri = [p[5] for p in parts if len(p) > 5 and p[5]]
                    isin_bitis = max(teslim_tarihleri) if teslim_tarihleri else ""

                    writer.writerow([
                        t["ikn"], t["firma"], t["ihale"],
                        display_money(t["total_amount"]),
                        len(parts),
                        sozlesme_tarihi, ihale_turu, ihale_usulu,
                        yak_maliyet, ihale_tarihi, ise_baslama,
                        parti_teslim_suresi, isin_bitis,
                    ])
            QMessageBox.information(self, "Başarılı", f"Tüm ihale bilgileri başarıyla dışa aktarıldı:\n{path}")
            log_action("CSV Dışa Aktar (Tüm İhale Bilgileri Özet)", f"Dosya: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"CSV dışa aktarma hatası:\n{e}")

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
        self.total_label.setText(f"<b>GENEL TOPLAM: {display_money(grand_total)}</b>")

        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(filtered))

        # Varsayılan sıralama: Yüklenici Adı (Türkçe karakter desteğiyle)
        filtered.sort(key=lambda f: tr_key(f["name"]))

        for i, f in enumerate(filtered):
            # Name
            self.table.setItem(i, 0, QTableWidgetItem(f["name"]))

            # Tender Count
            t_item = SortableTableWidgetItem(format_number(f["tender_count"]))
            t_item.setData(Qt.ItemDataRole.UserRole, f["tender_count"])
            t_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(i, 1, t_item)

            # Part Count
            c_item = SortableTableWidgetItem(format_number(f["part_count"]))
            c_item.setData(Qt.ItemDataRole.UserRole, f["part_count"])
            c_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(i, 2, c_item)

            # Total Volume
            v_item = SortableTableWidgetItem(display_money(f["volume"]))
            v_item.setData(Qt.ItemDataRole.UserRole, f["volume"])
            v_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.table.setItem(i, 3, v_item)

        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)

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

        # Takvim boyutu (%20 küçültüldü)
        self.calendar.setMinimumHeight(360)
        self.calendar.setMinimumWidth(440)
        self.calendar.setMaximumWidth(520)

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
        box_bg = "#f8fafc"
        box_border = "#e2e8f0"
        self.filter_box.setStyleSheet(f"#FilterBox {{ background-color: {box_bg}; border-radius: 8px; border: 1px solid {box_border}; padding: 10px; }}")
        filter_layout = QVBoxLayout(self.filter_box)
        self.cb_status = QComboBox()
        self.cb_status.addItems(["Tümü", "Sadece Bekleyenler", "Sadece Tamamlananlar"])
        self.cb_status.currentIndexChanged.connect(self.refresh_data)
        filter_layout.addWidget(self.cb_status)
        left_panel.addWidget(self.filter_box)

        # Aylık Özet
        self.summary_box = QFrame()
        self.summary_box.setObjectName("SummaryBox")
        box_bg = "#f8fafc"
        box_border = "#e2e8f0"
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
            lbl.setStyleSheet(f"color: {'#1e293b'}; font-size: 13px;")
            s_layout.addWidget(lbl)

        left_panel.addWidget(self.summary_box)
        left_panel.addStretch()

        # Sayfa (Ay) değiştiğinde özeti güncelle
        self.calendar.currentPageChanged.connect(self.update_monthly_summary)

        layout.addLayout(left_panel, stretch=0)  # Soldaki alan sabit

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

        layout.addLayout(right_panel, stretch=1)

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
                    is_completed = (len(r) > 11 and _is_checked(r[11]))

                    if filter_mode == "Sadece Bekleyenler" and is_completed: continue
                    if filter_mode == "Sadece Tamamlananlar" and not is_completed: continue

                    total_amount += parse_money(r[6])
                    firms.add(r[2])
                    tenders.add(r[1]) # IKN
                    batch_count += 1
            except:
                continue

        # UI Güncelleme
        self.lbl_month_total.setText(f"💰 Toplam Tutar: {display_money(total_amount)}")
        self.lbl_month_firms.setText(f"🏢 Firma Sayısı: {len(firms)}")
        self.lbl_month_tenders.setText(f"📋 Toplam İhale: {len(tenders)}")
        self.lbl_month_batches.setText(f"📦 Toplam Parti: {batch_count}")

        # Başlığı gösterilen aya göre güncelle
        tr_months = ["", "Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran", "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık"]
        self.lbl_month_title.setText(f"📊 {tr_months[month]} {year} Özeti")

    def update_calendar_styles(self):
        # Ana Takvim Stili
        bg_color = "#ffffff"
        text_color = "#1e293b"
        header_bg = "#5e35b1"
        grid_color = "#e2e8f0"
        alt_bg = "#f1f5f9"

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
        box_bg = "#f8fafc"
        box_border = "#e2e8f0"
        self.filter_box.setStyleSheet(f"#FilterBox {{ background-color: {box_bg}; border-radius: 8px; border: 1px solid {box_border}; padding: 10px; }}")
        self.summary_box.setStyleSheet(f"#SummaryBox {{ background-color: {box_bg}; border-radius: 8px; border: 1px solid {box_border}; padding: 10px; }}")

        for lbl in [self.lbl_month_total, self.lbl_month_firms, self.lbl_month_tenders, self.lbl_month_batches]:
            lbl.setStyleSheet(f"color: {'#1e293b'}; font-size: 13px;")

    def highlight_dates(self):
        fmt_clear = QTextCharFormat()
        year = self.calendar.yearShown()
        month = self.calendar.monthShown()
        days_in_month = QDate(year, month, 1).daysInMonth()
        for day in range(1, days_in_month + 1):
            self.calendar.setDateTextFormat(QDate(year, month, day), fmt_clear)

        filter_mode = self.cb_status.currentText()

        counts = {}

        for r in self.all_data:
            if not r[5]: continue

            is_completed = (len(r) > 11 and _is_checked(r[11]))

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
                    fmt.setBackground(QColor("#16a34a"))
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
            if item.widget():
                item.widget().hide()
                item.widget().deleteLater()

        selected_qdate = self.calendar.selectedDate()
        date_str = selected_qdate.toString("yyyy-MM-dd")
        self.detail_label.setText(f"📅 {selected_qdate.toString('dd.MM.yyyy')} Tarihindeki İşler")

        filter_mode = self.cb_status.currentText()

        found_data = []
        for r in self.all_data:
            if r[5] and r[5][:10] == date_str:
                is_completed = (len(r) > 11 and _is_checked(r[11]))
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
        self.current_status_filter = "active" # all, active, completed
        self.setup_ui()
        self.refresh_data()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Üst Buton Paneli
        top_btn_layout = QHBoxLayout()

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

        btn_export = QPushButton("📊 Verileri CSV Olarak Dışa Aktar")
        btn_export.setObjectName("InfoBtn")
        btn_export.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_export.clicked.connect(self.export_to_csv)
        top_btn_layout.addWidget(btn_export)

        btn_new = QPushButton("➕ Yeni İhale Ekle")
        btn_new.setToolTip("Yeni İhale Ekle (Ctrl+N)")
        btn_new.setObjectName("SuccessBtn")
        btn_new.clicked.connect(self.open_new_tender)
        top_btn_layout.addWidget(btn_new)

        top_btn_layout.addSpacing(40)

        top_btn_layout.addStretch()
        layout.addLayout(top_btn_layout)

        self.btn_active.setChecked(True)
        self.btn_all.clicked.connect(lambda: self.set_status_filter("all"))
        self.btn_active.clicked.connect(lambda: self.set_status_filter("active"))
        self.btn_completed.clicked.connect(lambda: self.set_status_filter("completed"))

        # Filtre Paneli
        f_panel = QHBoxLayout()
        self.search = QLineEdit(); self.search.setPlaceholderText("Metin ara...")
        btn_clr = QPushButton("Temizle"); btn_clr.setToolTip("Temizle (Alt+X)"); btn_clr.clicked.connect(self.clear_filters)

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
        self.table = QTableWidget();         self.table.setColumnCount(30)
        self.table.setAlternatingRowColors(True)
        self.table.setHorizontalHeaderLabels([
            "IKN", "Firma", "İhale Adı",
            "İhale Tarihi", "Sözl. Tarihi", "İşe Başlama", "Parti Teslim Süresi", "Parti Tarihi",
            "Parti No", "Miktar", "Malzeme Detayı", "Tutar",
            "Ambar", "Bşk. Haber", "Test B.", "Test S.", "Rapor", "Kabul", "Ödeme",
            "Açıklama", "İhale Türü", "İhale Usulü", "Yak. Maliyet", "Cari No", "Proje No", "Kart No",
            "Test Detay (B)", "Test Detay (S)", "Teslim Ambarı", "İşlem"
        ])

        # Sütun Genişlikleri
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(0, 100)  # IKN
        self.table.setColumnWidth(1, 150)  # Firma
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)  # Ihale Adi
        self.table.setColumnWidth(3, 100)  # İhale Tarihi
        self.table.setColumnWidth(4, 100)  # Sözl. Tarihi
        self.table.setColumnWidth(5, 100)  # İşe Başlama
        self.table.setColumnWidth(6, 100)  # Parti Teslim Süresi
        self.table.setColumnWidth(7, 90)   # Parti Tarihi
        self.table.setColumnWidth(8, 60)   # Parti No
        self.table.setColumnWidth(9, 80)   # Miktar
        self.table.setColumnWidth(10, 200) # Malzeme Detayi
        self.table.setColumnWidth(11, 120) # Tutar
        for i in range(12, 30):
            self.table.setColumnWidth(i, 100)
        self.table.setColumnWidth(2, 250) # İhale adı geniş kalsın
        self.table.setColumnWidth(28, 120) # Teslim Ambarı
        self.table.setColumnWidth(29, 130) # İşlem sütunu

        self.table.setSortingEnabled(True)

        # Toplu işlem için çoklu seçim ve sağ menü
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)

        layout.addWidget(self.table)
        # Kaydedilmiş sütun görünürlüğü ayarlarını yükle
        self.load_column_settings()


    def load_column_settings(self):
        settings = QSettings("IhaleSystem", f"UserPrefs/{Session.user}")
        # IKN(0), Firma(1), Ihale(2), Ihale Tarihi(3), Sozlesme(4), Ise Baslama(5), Parti Teslim(6), Parti Tarihi(7), Parti No(8), Miktar(9), Malzeme(10), Tutar(11), Aciklama(19), Teslim Ambari(28) DB:33
        min_indices = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 19, 28]

        has_settings = False
        for c in range(self.table.columnCount()):
            if settings.contains(f"column_visible_{c}"):
                has_settings = True
                break

        # Sütunları gizle/göster
        for col in range(self.table.columnCount()):
            # 'Islem' sütunu (index 29) her zaman görünür kalsın
            if col == 29:
                self.table.setColumnHidden(col, False)
                continue

            if has_settings:
                if settings.contains(f"column_visible_{col}"):
                    is_visible = settings.value(f"column_visible_{col}", type=bool)
                else:
                    is_visible = (col in min_indices)
                self.table.setColumnHidden(col, not is_visible)
            else:
                self.table.setColumnHidden(col, col not in min_indices)


    def toggle_date_filter_visibility(self, checked):
        self.date_start.setVisible(checked)
        self.date_sep_label.setVisible(checked)
        self.date_end.setVisible(checked)

    def export_to_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Verileri CSV Olarak Kaydet", "", "CSV Dosyası (*.csv)")
        if not path:
            return

        try:
            # "İşlem" sütunu (index 29) hariç tüm sütunları dışa aktar
            export_cols = [i for i in range(self.table.columnCount()) if i != 29]
            headers = [self.table.horizontalHeaderItem(i).text() for i in export_cols]

            with open(path, mode='w', encoding='utf-8-sig', newline='') as file:
                writer = csv.writer(file, delimiter=';')
                writer.writerow(headers)

                for row in range(self.table.rowCount()):
                    row_data = []
                    for col in export_cols:
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
            is_completed = (len(r) > 11 and _is_checked(r[11]))
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
            is_completed = (len(r) > 11 and _is_checked(r[11]))
            if self.current_status_filter == "active" and is_completed:
                continue
            if self.current_status_filter == "completed" and not is_completed:
                continue

            filtered.append(r)

        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(filtered))
        for row_idx, r in enumerate(filtered):
            # IKN, Firma, Ihale Adi (0-2)
            for i in range(3):
                item = QTableWidgetItem(str(r[i+1]))
                if i == 0:
                    item.setData(Qt.ItemDataRole.UserRole, r[0])
                self.table.setItem(row_idx, i, item)

            # Col 3: İhale Tarihi (DB 25)
            ihale_tarihi_raw = str(r[25])[:10] if len(r) > 25 and r[25] else ""
            self.table.setItem(row_idx, 3, QTableWidgetItem(format_date_tr(ihale_tarihi_raw)))

            # Col 4: Sözleşme Tarihi (DB 17)
            sozlesme_raw = str(r[17])[:10] if len(r) > 17 and r[17] else ""
            sozlesme_item = QTableWidgetItem(format_date_tr(sozlesme_raw))
            sozlesme_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row_idx, 4, sozlesme_item)

            # Col 5: İşe Başlama (DB 26)
            ise_baslama_raw = str(r[26])[:10] if len(r) > 26 and r[26] else ""
            self.table.setItem(row_idx, 5, QTableWidgetItem(format_date_tr(ise_baslama_raw)))

            # Col 6: Parti Teslim Süresi (DB 27)
            parti_suresi_val = str(r[27]) if len(r) > 27 and r[27] else "-"
            self.table.setItem(row_idx, 6, QTableWidgetItem(parti_suresi_val))

            # Col 7: Parti Tarihi (DB 5) – Sortable with color
            tarih_raw = str(r[5])[:10] if r[5] else ""
            tarih_item = SortableTableWidgetItem(format_date_tr(tarih_raw))
            tarih_item.setData(Qt.ItemDataRole.UserRole, tarih_raw)
            tarih_item.setTextAlignment(Qt.AlignCenter)
            is_completed = (len(r) > 11 and _is_checked(r[11]))
            date_color = get_date_color(tarih_raw, is_completed)
            if date_color:
                tarih_item.setBackground(QColor(date_color))
                tarih_item.setForeground(QColor("white"))
            self.table.setItem(row_idx, 7, tarih_item)

            # Col 8: Parti No (DB 4) – Sortable numeric
            parti_val = int(r[4]) if str(r[4]).isdigit() else 0
            parti_item = SortableTableWidgetItem(str(r[4]))
            parti_item.setData(Qt.ItemDataRole.UserRole, parti_val)
            parti_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row_idx, 8, parti_item)

            # Col 9: Miktar (DB 16)
            miktar_val = format_number(r[16]) if len(r) > 16 and r[16] else ""
            m_item = QTableWidgetItem(miktar_val)
            m_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row_idx, 9, m_item)

            # Col 10: Malzeme Detayı (DB 18)
            malzeme_val = str(r[18]) if len(r) > 18 and r[18] else ""
            mal_item = QTableWidgetItem(malzeme_val)
            mal_item.setToolTip(malzeme_val)
            self.table.setItem(row_idx, 10, mal_item)

            # Col 11: Tutar (DB 6) – Sortable numeric
            t_item = SortableTableWidgetItem(f"{display_money(r[6])}")
            t_item.setData(Qt.ItemDataRole.UserRole, float(r[6]) if r[6] else 0.0)
            t_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.table.setItem(row_idx, 11, t_item)

            # Cols 12-18: Durum sütunları (DB 7,19,8,9,10,11,13)
            for c, idx in enumerate([7, 19, 8, 9, 10, 11, 13], 12):
                val = r[idx] if idx < len(r) else 0.0
                it = QTableWidgetItem("✓" if _is_checked(val) else "○")
                it.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row_idx, c, it)

            # Col 19: Açıklama (DB 14)
            self.table.setItem(row_idx, 19, QTableWidgetItem(str(r[14]) if len(r) > 14 else ""))

            # Col 20: İhale Türü (DB 22)
            self.table.setItem(row_idx, 20, QTableWidgetItem(str(r[22]) if len(r) > 22 else "-"))

            # Col 21: İhale Usulü (DB 23)
            self.table.setItem(row_idx, 21, QTableWidgetItem(str(r[23]) if len(r) > 23 else "-"))

            # Col 22: Yak. Maliyet (DB 24) – Sortable numeric
            yak_val_raw = r[24] if len(r) > 24 and r[24] else 0.0
            try:
                if isinstance(yak_val_raw, str):
                    yak_val_num = float(yak_val_raw.replace('.', '').replace(',', '.'))
                else:
                    yak_val_num = float(yak_val_raw)
            except:
                yak_val_num = 0.0
            yak_item = SortableTableWidgetItem(f"{display_money(yak_val_num)}")
            yak_item.setData(Qt.ItemDataRole.UserRole, yak_val_num)
            yak_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.table.setItem(row_idx, 22, yak_item)

            # Col 23: Cari No (DB 28)
            val23 = str(r[28]) if len(r) > 28 and r[28] else ""
            if val23 and val23.replace('.', '').isdigit():
                val23 = "{:,}".format(int(val23.replace('.', ''))).replace(',', '.')
            self.table.setItem(row_idx, 23, QTableWidgetItem(val23))

            # Col 24: Proje No (DB 29)
            val24 = str(r[29]) if len(r) > 29 and r[29] else ""
            if val24 and val24.replace('.', '').isdigit():
                val24 = "{:,}".format(int(val24.replace('.', ''))).replace(',', '.')
            self.table.setItem(row_idx, 24, QTableWidgetItem(val24))

            # Col 25: Kart No (DB 30)
            val25 = str(r[30]) if len(r) > 30 and r[30] else ""
            if val25 and val25.replace('.', '').isdigit():
                val25 = "{:,}".format(int(val25.replace('.', ''))).replace(',', '.')
            self.table.setItem(row_idx, 25, QTableWidgetItem(val25))

            # Col 26: Test Detay (B) (DB 20)
            self.table.setItem(row_idx, 26, QTableWidgetItem(str(r[20]) if len(r) > 20 else "-"))

            # Col 27: Test Detay (S) (DB 21)
            self.table.setItem(row_idx, 27, QTableWidgetItem(str(r[21]) if len(r) > 21 else "-"))

            # Col 28: Teslim Ambarı (DB 33)
            amb_val = str(r[34]) if len(r) > 34 and r[34] else ""
            amb_item = QTableWidgetItem(amb_val)
            amb_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row_idx, 28, amb_item)

            # Col 29: İşlem Butonları
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(0, 0, 0, 0)
            action_layout.setSpacing(5)

            btn_edit = QPushButton("Düzenle")
            btn_edit.setStyleSheet("background-color: #ff9800; color: white; border-radius: 4px; padding: 4px;")
            btn_edit.clicked.connect(lambda ch, rec=r: self.open_edit(rec))
            action_layout.addWidget(btn_edit)

            if Session.can_delete:
                btn_delete = QPushButton("SİL")
                btn_delete.setStyleSheet("background-color: #f44336; color: white; border-radius: 4px; padding: 4px; font-weight: bold;")
                btn_delete.clicked.connect(lambda ch, rec=r: self.delete_row(rec))
                action_layout.addWidget(btn_delete)

            action_layout.addStretch()
            self.table.setCellWidget(row_idx, 29, action_widget)

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

    def show_context_menu(self, pos):
        selected_items = self.table.selectedItems()
        if not selected_items:
            return

        menu = QtWidgets.QMenu(self)
        action_bulk_edit = menu.addAction("✏️ Seçili Kayıtları Topluca Düzenle")
        action_delete_parts = menu.addAction("❌ Seçili Parti Verilerini Sil")
        action_new_batch = menu.addAction("➕ Yeni Parti Bilgisi Ekle")
        action_shift_dates = menu.addAction("↔️ Seçili Parti Son Teslim Tarihlerini Ötele")

        action = menu.exec(self.table.viewport().mapToGlobal(pos))

        if action == action_new_batch:
            self.open_new_batch()
        elif action == action_bulk_edit:
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
        elif action == action_delete_parts:
            selected_rows = set(item.row() for item in selected_items)
            records_to_del = []
            for row in selected_rows:
                ikn_item = self.table.item(row, 0)
                if ikn_item:
                    rowid = ikn_item.data(Qt.ItemDataRole.UserRole)
                    if rowid:
                        for r in self.all_data:
                            if r[0] == rowid:
                                records_to_del.append(r)
                                break
            if records_to_del:
                msg = QMessageBox(self)
                msg.setWindowTitle("Parti Silme Onayı")
                msg.setText(f"Seçili {len(records_to_del)} parti kaydını silmek istediğinize emin misiniz?")
                msg.setIcon(QMessageBox.Icon.Warning)
                msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if msg.exec() == QMessageBox.StandardButton.Yes:
                    deleted_count = 0
                    for r in records_to_del:
                        try:
                            delete_record(r[0])
                            log_action("Parti Silme", f"ID: {r[0]} | IKN: {r[1]} | Firma: {r[2]} | Parti: {r[4]}")
                            deleted_count += 1
                        except: pass
                    QMessageBox.information(self, "Başarılı", f"Toplam {deleted_count} parti silindi.")
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
            audit_log = f"Tarih Öteleme ({days} gün): {Session.user} ({timestamp})"

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("BEGIN")
            log_details = []
            try:
                for r in self.records:
                    rowid = r[0]
                    old_date_str = str(r[5])[:10] if r[5] else ""
                    if old_date_str:
                        old_date = datetime.strptime(old_date_str, "%Y-%m-%d")
                        new_date = old_date + timedelta(days=days)
                        new_date_str = new_date.strftime("%Y-%m-%d")

                        cursor.execute("UPDATE data SET `Parti Son Teslim Tarihi` = ?, `SonGuncelleme` = ? WHERE rowid = ?",
                                       (new_date_str, audit_log, rowid))

                        log_details.append(f"IKN: {r[1]}, Firma: {r[2]}, Parti: {r[4]}")
                conn.commit()
            except:
                conn.rollback()
                raise
            finally:
                conn.close()

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
        self.search_edit.setPlaceholderText("IKN, firma, tarih, kullanıcı, işlem veya detay...")
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
        btn_clr.setToolTip("Temizle (Alt+X)")
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
        self.table.setItemDelegateForColumn(4, WordWrapDelegate(4))
        self.table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        self.table.verticalHeader().setDefaultSectionSize(25)

        header = self.table.horizontalHeader()
        self.table.setColumnWidth(0, 70)   # ID
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
        QTimer.singleShot(50, self.recalc_row_heights)

    def recalc_row_heights(self):
        detay_col = self.table.columnWidth(4)
        if detay_col > 50:
            fm = self.table.fontMetrics()
            for i in range(self.table.rowCount()):
                item = self.table.item(i, 4)
                if item and item.text():
                    rect = fm.boundingRect(0, 0, detay_col - 10, 0, Qt.TextFlag.TextWordWrap, item.text())
                    self.table.setRowHeight(i, min(rect.height() + 5, 60))

    def _extract_ikn_firma(self, details):
        ikn = ""
        firma = ""
        if not details:
            return "-"
        s = str(details)
        # "IKN: xxx" desenini ara
        if "IKN:" in s:
            # IKN'dan sonraki kısmı al
            after_ikn = s.split("IKN:")[1].strip()
            # Virgül, | veya boşlukla biten kısmı al
            for sep in [",", "|", " "]:
                if sep in after_ikn:
                    ikn = after_ikn.split(sep)[0].strip()
                    break
            if not ikn:
                ikn = after_ikn.split()[0] if after_ikn else ""
        if "Firma:" in s:
            after_firma = s.split("Firma:")[1].strip()
            for sep in ["|", ","]:
                if sep in after_firma:
                    firma = after_firma.split(sep)[0].strip()
                    break
            else:
                firma = after_firma
        if ikn and firma:
            return f"{ikn} | {firma}"
        return ikn or firma or "-"

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
            self.table.setItem(i, 0, id_item)
            self.table.setItem(i, 1, QTableWidgetItem(str(log[1])))
            self.table.setItem(i, 2, QTableWidgetItem(str(log[2])))
            self.table.setItem(i, 3, QTableWidgetItem(str(log[3])))
            detay_item = QTableWidgetItem(str(log[4]))
            detay_item.setToolTip(str(log[4]))
            self.table.setItem(i, 4, detay_item)
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().setDefaultSectionSize(25)
        QTimer.singleShot(50, self.recalc_row_heights)

    def clear_log_filters(self):
        self.search_edit.clear()
        self.cb_user.setCurrentIndex(0)
        self.cb_action.setCurrentIndex(0)

# --- SETTINGS DIALOG ---
class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("⚙️ Ayarlar")
        self.setFixedWidth(800)
        self.parent_window = parent
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        tabs = QTabWidget()

        # Tab 1: Sütun Ayarları (DetailWidget'tan taşındı)
        col_tab = QWidget()
        col_layout = QVBoxLayout(col_tab)
        col_layout.addWidget(QLabel("<b>Tüm İhale ve Parti Bilgileri Tablosu Sütun Görünürlüğü:</b>"))

        # Hızlı Ayar Butonları
        btn_row = QHBoxLayout()
        btn_all = QPushButton("✅ Tüm Sütunları Göster")
        btn_min = QPushButton("📋 Asgari Sütunları Göster")
        btn_all.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_min.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_all.clicked.connect(self.select_all_columns)
        btn_min.clicked.connect(self.select_min_columns)
        btn_row.addWidget(btn_all)
        btn_row.addWidget(btn_min)
        btn_row.addStretch()
        col_layout.addLayout(btn_row)

        self.col_checkboxes = [] # (index or list of indices, checkbox_obj)
        detail_widget = self.parent_window.detail_widget

        # Daha açıklayıcı isimler için harita
        column_map = {
            "IKN": "İhale Kayıt No (İKN)",
            "İhale Adı": "İhale / İş Adı",
            "Sözl. Tarihi": "Sözleşme Tarihi",
            "Parti Tarihi": "Teslim / Termin Tarihi",
            "Miktar": "Parti Miktarı",
            "Tutar": "Parti Tutarı (TL)",
            "Açıklama": "Açıklama",
            "İhale Türü": "İhale Türü (Mal/Hizmet)",
            "İhale Usulü": "İhale Usulü",
            "Yak. Maliyet": "Yaklaşık Maliyet",
            "İhale Tarihi": "İhale Tarihi",
            "İşe Başlama": "İşe Başlama Tarihi",
            "Parti Teslim Süresi": "Parti Teslim Süresi (Hesaplanan)",
            "Cari No": "Cari No",
            "Proje No": "Proje No",
            "Kart No": " Kart No",
            "Test Detay (B)": "Test Başladı Notu",
            "Test Detay (S)": "Test Sonuç Notu",
            "Teslim Ambarı": "Teslim Ambarı",
        }

        scroll = QScrollArea()
        scroll_content = QWidget()
        scroll_grid = QGridLayout(scroll_content)
        scroll_grid.setSpacing(10)

        # Temel Sütunlar ve Yeni İhale Bilgileri
        # 0:IKN, 1:Firma, 2:İhale Adı, 3:İhale Tarihi, 4:Sözl. Tarihi, 5:İşe Başlama, 6:Parti Teslim Süresi,
        # 7:Parti Tarihi, 8:Parti No, 9:Miktar, 10:Malzeme Detayı, 11:Tutar, 19:Açıklama,
        # 20:İhale Türü, 21:İhale Usulü, 22:Yak. Maliyet, 23:Cari No, 24:Proje No, 25:Kart No, 28:Teslim Ambarı
        basic_indices = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 19, 20, 21, 22, 23, 24, 25, 28]
        grid_idx = 0

        for col in basic_indices:
            header_item = detail_widget.table.horizontalHeaderItem(col)
            orig_label = header_item.text() if header_item else f"Sütun {col}"
            display_label = column_map.get(orig_label, orig_label)

            cb = QCheckBox(display_label)
            cb.setChecked(not detail_widget.table.isColumnHidden(col))
            cb.setStyleSheet("font-size: 12px; padding: 2px;")

            scroll_grid.addWidget(cb, grid_idx // 2, grid_idx % 2)
            self.col_checkboxes.append((col, cb))
            grid_idx += 1

        # İşlem Adımları Grubu (12-18 arası sütunlar + 26, 27)
        action_step_indices = list(range(12, 19)) + [26, 27]
        cb_action_group = QCheckBox("🔄 İşlem Adımları ve Detaylar")
        # Eğer adımlardan en az biri görünürse grubu seçili başlat
        any_visible = any(not detail_widget.table.isColumnHidden(i) for i in action_step_indices)
        cb_action_group.setChecked(any_visible)
        cb_action_group.setStyleSheet("font-size: 12px; font-weight: bold; color: #6366f1; padding: 2px;")

        scroll_grid.addWidget(cb_action_group, grid_idx // 2, grid_idx % 2)
        self.col_checkboxes.append((action_step_indices, cb_action_group))

        scroll.setWidget(scroll_content)
        scroll.setWidgetResizable(True)
        col_layout.addWidget(scroll)

        tabs.addTab(col_tab, "📊 Sütun Ayarları")

        # Tab 2: Laboratuvar Listesi
        lab_tab = QWidget()
        lab_layout = QVBoxLayout(lab_tab)
        lab_layout.addWidget(QLabel("<b>Laboratuvar Listesi:</b>"))

        self.lab_list_widget = QtWidgets.QListWidget()
        self.refresh_lab_list()
        lab_layout.addWidget(self.lab_list_widget)

        lab_btn_row = QHBoxLayout()
        self.lab_input = QLineEdit()
        self.lab_input.setPlaceholderText("Yeni laboratuvar adı...")
        btn_add_lab = QPushButton("Ekle")
        btn_add_lab.setObjectName("SuccessBtn")
        btn_add_lab.clicked.connect(self.add_lab)

        btn_edit_lab = QPushButton("Düzenle")
        btn_edit_lab.setObjectName("PrimaryBtn")
        btn_edit_lab.clicked.connect(self.edit_lab)

        btn_del_lab = QPushButton("Seçiliyi Sil")
        btn_del_lab.setObjectName("DangerBtn")
        btn_del_lab.clicked.connect(self.delete_lab)

        lab_btn_row.addWidget(self.lab_input)
        lab_btn_row.addWidget(btn_add_lab)
        lab_btn_row.addWidget(btn_edit_lab)
        lab_btn_row.addWidget(btn_del_lab)
        lab_layout.addLayout(lab_btn_row)

        tabs.addTab(lab_tab, "🧪 Laboratuvarlar")

        # Tab 3: İhale Türü Listesi
        turu_tab = QWidget()
        turu_layout = QVBoxLayout(turu_tab)
        turu_layout.addWidget(QLabel("<b>İhale Türü Listesi:</b>"))

        self.turu_list_widget = QtWidgets.QListWidget()
        self.refresh_turu_list()
        turu_layout.addWidget(self.turu_list_widget)

        turu_btn_row = QHBoxLayout()
        self.turu_input = QLineEdit()
        self.turu_input.setPlaceholderText("Yeni ihale türü...")
        btn_add_turu = QPushButton("Ekle")
        btn_add_turu.setObjectName("SuccessBtn")
        btn_add_turu.clicked.connect(self.add_turu)

        btn_edit_turu = QPushButton("Düzenle")
        btn_edit_turu.setObjectName("PrimaryBtn")
        btn_edit_turu.clicked.connect(self.edit_turu)

        btn_del_turu = QPushButton("Seçiliyi Sil")
        btn_del_turu.setObjectName("DangerBtn")
        btn_del_turu.clicked.connect(self.delete_turu)

        turu_btn_row.addWidget(self.turu_input)
        turu_btn_row.addWidget(btn_add_turu)
        turu_btn_row.addWidget(btn_edit_turu)
        turu_btn_row.addWidget(btn_del_turu)
        turu_layout.addLayout(turu_btn_row)

        tabs.addTab(turu_tab, "📋 İhale Türü")

        # Tab 4: İhale Usulü Listesi
        usulu_tab = QWidget()
        usulu_layout = QVBoxLayout(usulu_tab)
        usulu_layout.addWidget(QLabel("<b>İhale Usulü Listesi:</b>"))

        self.usulu_list_widget = QtWidgets.QListWidget()
        self.refresh_usulu_list()
        usulu_layout.addWidget(self.usulu_list_widget)

        usulu_btn_row = QHBoxLayout()
        self.usulu_input = QLineEdit()
        self.usulu_input.setPlaceholderText("Yeni ihale usulü...")
        btn_add_usulu = QPushButton("Ekle")
        btn_add_usulu.setObjectName("SuccessBtn")
        btn_add_usulu.clicked.connect(self.add_usulu)

        btn_edit_usulu = QPushButton("Düzenle")
        btn_edit_usulu.setObjectName("PrimaryBtn")
        btn_edit_usulu.clicked.connect(self.edit_usulu)

        btn_del_usulu = QPushButton("Seçiliyi Sil")
        btn_del_usulu.setObjectName("DangerBtn")
        btn_del_usulu.clicked.connect(self.delete_usulu)

        usulu_btn_row.addWidget(self.usulu_input)
        usulu_btn_row.addWidget(btn_add_usulu)
        usulu_btn_row.addWidget(btn_edit_usulu)
        usulu_btn_row.addWidget(btn_del_usulu)
        usulu_layout.addLayout(usulu_btn_row)

        tabs.addTab(usulu_tab, "📋 İhale Usulü")

        # Tab 5: Ambar Yönetimi
        ambar_tab = QWidget()
        ambar_layout = QVBoxLayout(ambar_tab)
        ambar_layout.addWidget(QLabel("<b>Teslim Ambarı Listesi:</b>"))

        self.ambar_list_widget = QtWidgets.QListWidget()
        self.refresh_ambar_list()
        ambar_layout.addWidget(self.ambar_list_widget)

        ambar_btn_row = QHBoxLayout()
        self.ambar_input = QLineEdit()
        self.ambar_input.setPlaceholderText("Yeni ambar adı...")
        btn_add_ambar = QPushButton("Ekle")
        btn_add_ambar.setObjectName("SuccessBtn")
        btn_add_ambar.clicked.connect(self.add_ambar)

        btn_edit_ambar = QPushButton("Düzenle")
        btn_edit_ambar.setObjectName("PrimaryBtn")
        btn_edit_ambar.clicked.connect(self.edit_ambar)

        btn_del_ambar = QPushButton("Seçiliyi Sil")
        btn_del_ambar.setObjectName("DangerBtn")
        btn_del_ambar.clicked.connect(self.delete_ambar)

        ambar_btn_row.addWidget(self.ambar_input)
        ambar_btn_row.addWidget(btn_add_ambar)
        ambar_btn_row.addWidget(btn_edit_ambar)
        ambar_btn_row.addWidget(btn_del_ambar)
        ambar_layout.addLayout(ambar_btn_row)

        tabs.addTab(ambar_tab, "🏭 Ambarlar")

        # Tab 6: Yedek Yönetimi
        backup_tab = QWidget()
        backup_layout = QVBoxLayout(backup_tab)
        backup_layout.addWidget(QLabel("<b>💾 Yedek Dosyaları:</b>"))

        self.backup_list = QtWidgets.QListWidget()
        backup_layout.addWidget(self.backup_list)

        backup_btn_row = QHBoxLayout()
        btn_refresh_backup = QPushButton("🔄 Listeyi Yenile")
        btn_refresh_backup.clicked.connect(self.refresh_backup_list)
        backup_btn_row.addWidget(btn_refresh_backup)

        btn_backup_now = QPushButton("💾 Yedek Al")
        btn_backup_now.setObjectName("SuccessBtn")
        btn_backup_now.clicked.connect(self.do_backup)
        backup_btn_row.addWidget(btn_backup_now)

        btn_restore = QPushButton("📥 Seçili Yedeği Geri Yükle")
        btn_restore.setObjectName("WarningBtn")
        btn_restore.clicked.connect(self.restore_backup)
        backup_btn_row.addWidget(btn_restore)

        btn_delete_backup = QPushButton("🗑️ Seçili Yedeği Sil")
        btn_delete_backup.setObjectName("DangerBtn")
        btn_delete_backup.clicked.connect(self.delete_backup)
        backup_btn_row.addWidget(btn_delete_backup)

        backup_layout.addLayout(backup_btn_row)
        self.refresh_backup_list()
        tabs.addTab(backup_tab, "💾 Yedek Yönetimi")

        layout.addWidget(tabs)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        btns.button(QDialogButtonBox.StandardButton.Save).setText("Kaydet ve Uygula")
        btns.button(QDialogButtonBox.StandardButton.Cancel).setText("Kapat")
        btns.accepted.connect(self.save_settings)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def refresh_lab_list(self):
        self.lab_list_widget.clear()
        labs = get_labs()
        for lab in labs:
            self.lab_list_widget.addItem(lab)

    def add_lab(self):
        name = self.lab_input.text().strip()
        if not name: return
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO labs (name) VALUES (?)", (name,))
            conn.commit()
            conn.close()
            self.lab_input.clear()
            self.refresh_lab_list()
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Uyarı", "Bu laboratuvar zaten listede mevcut.")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Hata oluştu: {e}")

    def delete_lab(self):
        current_item = self.lab_list_widget.currentItem()
        if not current_item: return
        name = current_item.text()
        confirm = QMessageBox.question(self, "Onay", f"'{name}' laboratuvarını silmek istediğinize emin misiniz?",
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm != QMessageBox.StandardButton.Yes: return
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM labs WHERE name = ?", (name,))
            conn.commit()
            conn.close()
            self.refresh_lab_list()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Silme hatası: {e}")

    def edit_lab(self):
        current_item = self.lab_list_widget.currentItem()
        if not current_item:
            QMessageBox.warning(self, "Uyarı", "Lütfen düzenlemek istediğiniz laboratuvarı seçin.")
            return
        old_name = current_item.text()
        new_name, ok = QtWidgets.QInputDialog.getText(self, "Laboratuvar Düzenle", "Laboratuvar Adı:", QLineEdit.EchoMode.Normal, old_name)
        if ok and new_name.strip() and new_name.strip() != old_name:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("UPDATE labs SET name = ? WHERE name = ?", (new_name.strip(), old_name))
                conn.commit()
                conn.close()
                self.refresh_lab_list()
            except sqlite3.IntegrityError:
                QMessageBox.warning(self, "Uyarı", "Bu isimde bir laboratuvar zaten mevcut.")
            except Exception as e:
                QMessageBox.critical(self, "Hata", f"Düzenleme hatası: {e}")

    def save_settings(self):
        # Sütun ayarlarını uygula ve kaydet
        detail_widget = self.parent_window.detail_widget
        settings = QSettings("IhaleSystem", f"UserPrefs/{Session.user}")

        for col_data, cb in self.col_checkboxes:
            is_visible = cb.isChecked()
            if isinstance(col_data, list):
                # Grup sütunları (İşlem Adımları)
                for idx in col_data:
                    detail_widget.table.setColumnHidden(idx, not is_visible)
                    settings.setValue(f"column_visible_{idx}", is_visible)
            else:
                # Tekil sütun
                detail_widget.table.setColumnHidden(col_data, not is_visible)
                settings.setValue(f"column_visible_{col_data}", is_visible)

        QMessageBox.information(self, "Başarılı", "Ayarlar kaydedildi ve uygulandı.")
        self.accept()

    def select_all_columns(self):
        """Tüm sütunları seçili hale getirir."""
        for _, cb in self.col_checkboxes:
            cb.setChecked(True)

    def select_min_columns(self):
        """Sadece asgari/zorunlu sütunları seçili bırakır."""
        # Asgari Sütun İndeksleri: IKN(0), Firma(1), İhale Adı(2), Parti Tarihi(7), Parti No(8), Miktar(9), Tutar(11)
        min_indices = [0, 1, 2, 7, 8, 9, 11]
        for col_data, cb in self.col_checkboxes:
            if isinstance(col_data, list):
                cb.setChecked(False) # İşlem adımları asgari değildir
            else:
                cb.setChecked(col_data in min_indices)

    # --- Yedek Yönetimi ---
    def get_backup_dir(self):
        if getattr(sys, 'frozen', False):
            base = os.path.dirname(sys.executable)
        else:
            base = os.path.dirname(os.path.abspath(__file__))
        d = os.path.join(base, 'Yedekler')
        os.makedirs(d, exist_ok=True)
        return d

    def refresh_backup_list(self):
        self.backup_list.clear()
        backup_dir = self.get_backup_dir()
        if not os.path.exists(backup_dir):
            return
        files = sorted([f for f in os.listdir(backup_dir) if f.endswith('.db')], reverse=True)
        for f in files:
            fpath = os.path.join(backup_dir, f)
            size = os.path.getsize(fpath)
            mtime = datetime.fromtimestamp(os.path.getmtime(fpath)).strftime("%d.%m.%Y %H:%M")
            self.backup_list.addItem(f"[{mtime}] {f} ({size/1024:.0f} KB)")

    def do_backup(self):
        backup_dir = self.get_backup_dir()
        if getattr(sys, 'frozen', False):
            base = os.path.dirname(sys.executable)
        else:
            base = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(base, 'veriler.db')
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        backup_file = os.path.join(backup_dir, f"veriler_yedek_{timestamp}.db")
        try:
            shutil.copy(db_path, backup_file)
            log_action("Manuel Yedekleme", f"Dosya: {backup_file}")
            QMessageBox.information(self, "Başarılı", f"Yedek alındı:\n{backup_file}")
            self.refresh_backup_list()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Yedekleme hatası: {e}")

    def restore_backup(self):
        current = self.backup_list.currentItem()
        if not current:
            QMessageBox.warning(self, "Uyarı", "Lütfen bir yedek dosyası seçin.")
            return
        name = current.text()
        fname = name.split("] ", 1)[-1].split(" (")[0] if "] " in name else name

        # Önce mevcut veritabanının yedeğini al
        QMessageBox.information(self, "Yedekleniyor",
            "Geri yüklemeden önce mevcut veritabanının yedeği alınacak.")
        self.do_backup()

        reply = QMessageBox.question(self, "Geri Yükle",
            f"'{fname}' dosyasından geri yüklemek tüm mevcut verilerinizi değiştirir!\n\nDevam etmek istediğinize emin misiniz?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        backup_dir = self.get_backup_dir()
        backup_path = os.path.join(backup_dir, fname)
        if not os.path.exists(backup_path):
            QMessageBox.critical(self, "Hata", "Dosya bulunamadı.")
            return
        if getattr(sys, 'frozen', False):
            base = os.path.dirname(sys.executable)
        else:
            base = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(base, 'veriler.db')
        try:
            shutil.copy(backup_path, db_path)
            log_action("Yedek Geri Yükleme", f"Dosya: {fname}")
            QMessageBox.information(self, "Başarılı", "Veritabanı geri yüklendi. Uygulamanın yeniden başlatılması önerilir.")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Geri yükleme hatası: {e}")

    def delete_backup(self):
        current = self.backup_list.currentItem()
        if not current:
            return
        name = current.text()
        fname = name.split("] ", 1)[-1].split(" (")[0] if "] " in name else name
        reply = QMessageBox.question(self, "Silme Onayı",
            f"'{fname}' yedek dosyasını silmek istediğinize emin misiniz?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        backup_dir = self.get_backup_dir()
        fpath = os.path.join(backup_dir, fname)
        try:
            os.remove(fpath)
            log_action("Yedek Silme", f"Dosya: {fname}")
            self.refresh_backup_list()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Silme hatası: {e}")

    # --- İhale Türü Yönetimi ---
    def refresh_turu_list(self):
        self.turu_list_widget.clear()
        for item in get_ihale_turu_list():
            self.turu_list_widget.addItem(item)

    def add_turu(self):
        name = self.turu_input.text().strip()
        if not name: return
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO ihale_turu_list (name) VALUES (?)", (name,))
            conn.commit()
            conn.close()
            self.turu_input.clear()
            self.refresh_turu_list()
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Uyarı", "Bu ihale türü zaten listede mevcut.")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Hata oluştu: {e}")

    def delete_turu(self):
        current_item = self.turu_list_widget.currentItem()
        if not current_item: return
        name = current_item.text()
        confirm = QMessageBox.question(self, "Onay", f"'{name}' ihale türünü silmek istediğinize emin misiniz?",
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm != QMessageBox.StandardButton.Yes: return
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM ihale_turu_list WHERE name = ?", (name,))
            conn.commit()
            conn.close()
            self.refresh_turu_list()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Silme hatası: {e}")

    def edit_turu(self):
        current_item = self.turu_list_widget.currentItem()
        if not current_item:
            QMessageBox.warning(self, "Uyarı", "Lütfen düzenlemek istediğiniz ihale türünü seçin.")
            return
        old_name = current_item.text()
        new_name, ok = QtWidgets.QInputDialog.getText(self, "İhale Türü Düzenle", "İhale Türü Adı:", QLineEdit.EchoMode.Normal, old_name)
        if ok and new_name.strip() and new_name.strip() != old_name:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("UPDATE ihale_turu_list SET name = ? WHERE name = ?", (new_name.strip(), old_name))
                conn.commit()
                conn.close()
                self.refresh_turu_list()
            except sqlite3.IntegrityError:
                QMessageBox.warning(self, "Uyarı", "Bu isimde bir ihale türü zaten mevcut.")
            except Exception as e:
                QMessageBox.critical(self, "Hata", f"Düzenleme hatası: {e}")

    # --- İhale Usulü Yönetimi ---
    def refresh_usulu_list(self):
        self.usulu_list_widget.clear()
        for item in get_ihale_usulu_list():
            self.usulu_list_widget.addItem(item)

    def add_usulu(self):
        name = self.usulu_input.text().strip()
        if not name: return
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO ihale_usulu_list (name) VALUES (?)", (name,))
            conn.commit()
            conn.close()
            self.usulu_input.clear()
            self.refresh_usulu_list()
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Uyarı", "Bu ihale usulü zaten listede mevcut.")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Hata oluştu: {e}")

    def delete_usulu(self):
        current_item = self.usulu_list_widget.currentItem()
        if not current_item: return
        name = current_item.text()
        confirm = QMessageBox.question(self, "Onay", f"'{name}' ihale usulünü silmek istediğinize emin misiniz?",
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm != QMessageBox.StandardButton.Yes: return
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM ihale_usulu_list WHERE name = ?", (name,))
            conn.commit()
            conn.close()
            self.refresh_usulu_list()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Silme hatası: {e}")

    def edit_usulu(self):
        current_item = self.usulu_list_widget.currentItem()
        if not current_item:
            QMessageBox.warning(self, "Uyarı", "Lütfen düzenlemek istediğiniz ihale usulünü seçin.")
            return
        old_name = current_item.text()
        new_name, ok = QtWidgets.QInputDialog.getText(self, "İhale Usulü Düzenle", "İhale Usulü Adı:", QLineEdit.EchoMode.Normal, old_name)
        if ok and new_name.strip() and new_name.strip() != old_name:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("UPDATE ihale_usulu_list SET name = ? WHERE name = ?", (new_name.strip(), old_name))
                conn.commit()
                conn.close()
                self.refresh_usulu_list()
            except sqlite3.IntegrityError:
                QMessageBox.warning(self, "Uyarı", "Bu isimde bir ihale usulü zaten mevcut.")
            except Exception as e:
                QMessageBox.critical(self, "Hata", f"Düzenleme hatası: {e}")

    # --- Ambar Yönetimi ---
    def refresh_ambar_list(self):
        self.ambar_list_widget.clear()
        for amb in get_ambar_list():
            self.ambar_list_widget.addItem(amb)

    def add_ambar(self):
        name = self.ambar_input.text().strip()
        if not name: return
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO ambarlar (name) VALUES (?)", (name,))
            conn.commit()
            conn.close()
            self.ambar_input.clear()
            self.refresh_ambar_list()
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Uyarı", "Bu ambar zaten listede mevcut.")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Hata oluştu: {e}")

    def delete_ambar(self):
        current_item = self.ambar_list_widget.currentItem()
        if not current_item: return
        name = current_item.text()
        confirm = QMessageBox.question(self, "Onay", f"'{name}' ambarını silmek istediğinize emin misiniz?",
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm != QMessageBox.StandardButton.Yes: return
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM ambarlar WHERE name = ?", (name,))
            conn.commit()
            conn.close()
            self.refresh_ambar_list()
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Silme hatası: {e}")

    def edit_ambar(self):
        current_item = self.ambar_list_widget.currentItem()
        if not current_item:
            QMessageBox.warning(self, "Uyarı", "Lütfen düzenlemek istediğiniz ambarı seçin.")
            return
        old_name = current_item.text()
        new_name, ok = QtWidgets.QInputDialog.getText(self, "Ambar Düzenle", "Ambar Adı:", QLineEdit.EchoMode.Normal, old_name)
        if ok and new_name.strip() and new_name.strip() != old_name:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("UPDATE ambarlar SET name = ? WHERE name = ?", (new_name.strip(), old_name))
                conn.commit()
                conn.close()
                self.refresh_ambar_list()
            except sqlite3.IntegrityError:
                QMessageBox.warning(self, "Uyarı", "Bu isimde bir ambar zaten mevcut.")
            except Exception as e:
                QMessageBox.critical(self, "Hata", f"Düzenleme hatası: {e}")

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
        <h3 style='color: #6366f1; margin-bottom:0;'>İhale Takip Uygulaması v7.52</h3>
        <br>
        <b>Geliştirici Bilgileri:</b></p>
        <ul>
        <li>Vibe Coder: Mustafa Halil GÖRENTAŞ</li>
        <li>Kaynak Kod: <a href="https://github.com/mhalil/ihale_takip_sistemi">github.com/mhalil/ihale_takip_sistemi</a></li>
        </ul>
        <p><b>Teknik Bilgiler:</b></p>
        <ul>
            <li>Platform: Google Antigravity ve OpenCode</li>
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

class ShortcutsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Klavye Kısayolları")
        self.setFixedSize(520, 520)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)

        title = QLabel("Klavye Kısayolları")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #1e293b;")
        layout.addWidget(title, alignment=Qt.AlignCenter)

        layout.addSpacing(12)

        shortcuts = [
            ("Ctrl+N", "Yeni ihale kaydı ekle"),
            ("Ctrl+F", "Arama çubuğuna git"),
            ("Alt+A", "Ayarlar penceresini aç"),
            ("Alt+X", "Filtreyi temizle"),
            ("F5", "Tüm verileri yenile, Parti teslim sürelerini hesapla"),
            ("Ctrl+1", "Güncel İhale sekmesine geç"),
            ("Ctrl+2", "Tüm İhale Bilgileri sekmesine geç"),
            ("Ctrl+3", "Takvim Görünümü sekmesine geç"),
            ("Ctrl+4", "Sözleşme Bilgileri sekmesine geç"),
            ("Ctrl+5", "Firma Özetleri sekmesine geç"),
            ("Ctrl+6", "İşlem Kayıtları sekmesine geç"),
        ]

        table = QTableWidget(len(shortcuts), 2)
        table.setHorizontalHeaderLabels(["Kısayol", "Açıklama"])
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        table.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        for row, (key, desc) in enumerate(shortcuts):
            item_key = QTableWidgetItem(key)
            item_key.setTextAlignment(Qt.AlignCenter)
            font = QFont()
            font.setBold(True)
            font.setFamily("Consolas")
            item_key.setFont(font)
            item_key.setForeground(QColor("#6366f1"))
            table.setItem(row, 0, item_key)

            item_desc = QTableWidgetItem(desc)
            table.setItem(row, 1, item_desc)

        table.setMinimumHeight(len(shortcuts) * 32 + 30)
        table.setMaximumHeight(len(shortcuts) * 32 + 30)
        layout.addWidget(table)

        layout.addSpacing(12)

        btn_close = QPushButton("Kapat")
        btn_close.setFixedWidth(100)
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close, alignment=Qt.AlignCenter)

# --- ANA PENCERE ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("İhale (Sözleşme) Takip Sistemi")
        self.resize(1700, 900)
        self.showMaximized()

        app.setStyleSheet(LIGHT_STYLE)

        central = QWidget(); self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Üst Bar (Tema Değiştirici)
        top_bar = QHBoxLayout()
        top_bar.addStretch()

        self.btn_user = QPushButton(f"👤 {Session.user}")
        self.btn_user.setObjectName("PrimaryBtn")
        self.btn_user.setFixedWidth(120)
        self.btn_user.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_user.clicked.connect(self.show_user_mgmt)
        top_bar.addWidget(self.btn_user)

        top_bar.addSpacing(5)

        self.btn_settings = QPushButton("⚙️ Ayarlar")
        self.btn_settings.setToolTip("Ayarlar (Alt+A)")
        self.btn_settings.setObjectName("PrimaryBtn")
        self.btn_settings.setFixedWidth(110)
        self.btn_settings.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_settings.clicked.connect(self.show_settings)
        top_bar.addWidget(self.btn_settings)

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

        top_bar.addSpacing(15)

        self.btn_shortcuts = QPushButton("⌨️ Kısayollar")
        self.btn_shortcuts.setObjectName("PrimaryBtn")
        self.btn_shortcuts.clicked.connect(self.show_shortcuts)
        self.btn_shortcuts.setFixedWidth(120)
        self.btn_shortcuts.setCursor(Qt.CursorShape.PointingHandCursor)
        top_bar.addWidget(self.btn_shortcuts)

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
        self.tabs.addTab(self.detail_widget, "📋 Tüm İhale ve Parti Bilgileri")
        self.tabs.addTab(self.calendar_widget, "📅 Takvim Görünümü")
        self.tabs.addTab(self.tender_widget, "🏢 Sözleşme Bilgileri")
        self.tabs.addTab(self.firm_widget, "🏭 Firma Özetleri")

        if Session.can_view_logs:
            self.tabs.addTab(self.log_widget, "📜 İşlem Kayıtları")

        tab_bar = self.tabs.tabBar()
        tab_keys = ["Ctrl+1", "Ctrl+2", "Ctrl+3", "Ctrl+4", "Ctrl+5", "Ctrl+6"]
        for i in range(tab_bar.count()):
            tab_bar.setTabToolTip(i, f"{tab_bar.tabText(i)} ({tab_keys[i]})")

        layout.addWidget(self.tabs)

        # Klavye kısayolları (widget'lar hazır olduktan sonra)
        self.setup_shortcuts()

    def refresh_all(self):
        recalculate_parti_teslim_suresi()
        self.summary_widget.refresh_summary()
        self.calendar_widget.refresh_data()
        self.detail_widget.refresh_data()
        self.tender_widget.refresh_data()
        self.firm_widget.refresh_data()
        if Session.can_view_logs:
            self.log_widget.refresh_logs()

    def show_about(self):
        AboutDialog(self).exec()

    def show_shortcuts(self):
        ShortcutsDialog(self).exec()

    def show_user_mgmt(self):
        UserManagementDialog(self).exec()

    def show_settings(self):
        SettingsDialog(self).exec()

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
            Session.logout()
            settings = QSettings("IhaleSystem", "LoginSettings")
            settings.setValue("auto_login", "false")
            # Set flag for main loop
            self.logout_requested = True
            self.close()

    def setup_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+N"), self, self.detail_widget.open_new_tender)
        QShortcut(QKeySequence("Ctrl+F"), self, self.focus_search)
        QShortcut(QKeySequence("Alt+A"), self, self.show_settings)
        QShortcut(QKeySequence("F5"), self, self.refresh_all)
        QShortcut(QKeySequence("Alt+X"), self, self.clear_active_tab)
        for i, key in enumerate(["Ctrl+1", "Ctrl+2", "Ctrl+3", "Ctrl+4", "Ctrl+5", "Ctrl+6"],0):
            QShortcut(QKeySequence(key), self, lambda idx=i: self.tabs.setCurrentIndex(idx))

    def clear_active_tab(self):
        w = self.tabs.currentWidget()
        if w == self.summary_widget:
            self.summary_widget.clear_filters()
        elif w == self.detail_widget:
            self.detail_widget.clear_filters()
        elif w == self.tender_widget:
            self.tender_widget.clear_search()
        elif w == self.firm_widget:
            self.firm_widget.clear_filters()
        elif w == self.log_widget:
            self.log_widget.clear_log_filters()

    def focus_search(self):
        w = self.tabs.currentWidget()
        if w == self.summary_widget:
            self.summary_widget.search.setFocus()
        elif w == self.detail_widget:
            self.detail_widget.search.setFocus()
        elif w == self.tender_widget:
            self.tender_widget.search_edit.setFocus()
        elif w == self.firm_widget:
            self.firm_widget.search_edit.setFocus()
        elif w == self.log_widget:
            self.log_widget.search_edit.setFocus()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Veritabanı migration (yeni alanları otomatik ekle)
    try:
        run_migrations()
    except Exception as e:
        print(f"Migration hatası: {e}")

    # Veritabanını kontrol et ve gerekirse haftalık yedek al
    try:
        check_and_create_backup()
    except Exception as e:
        print(f"Yedekleme başlangıç hatası: {e}")

    settings = QSettings("IhaleSystem", "LoginSettings")

    app.setStyleSheet(LIGHT_STYLE)

    main_window = None
    while True:
        auto_login = settings.value("auto_login", "false") == "true"
        login_success = False

        if auto_login:
            username = settings.value("username", "")
            password = settings.value("password", "")
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
                user_data = cursor.fetchone()
                if user_data:
                    role = user_data[2] if len(user_data) > 2 else ("admin" if username == "admin" else "user")
                    Session.login(username, role)
                    login_success = True
                conn.close()
            except Exception as e:
                print(f"Otomatik giriş veritabanı hatası: {e}")

        if not login_success:
            login = LoginDialog()
            if login.exec() == QDialog.DialogCode.Accepted:
                login_success = True
            else:
                break # Kullanıcı giriş penceresini kapattı

        if login_success:
            try:
                # Ana pencereyi yükle
                main_window = MainWindow()
                main_window.logout_requested = False
                main_window.show()
                app.exec()

                if main_window.logout_requested:
                    settings.setValue("auto_login", "false")
                    continue
                else:
                    break
            except Exception as e:
                QMessageBox.critical(None, "Kritik Hata", f"Uygulama ana ekranı yüklenirken hata oluştu:\n{e}")
                break
        else:
            break

    sys.exit(0)
