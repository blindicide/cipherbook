#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ПК-К-01 "Шифроблокнот" — MVP
Автор: Руслан + ChatGPT
Лицензия: MIT

Описание:
  Первая версия графического приложения на PyQt6:
  • Вкладка «Пароли»: генерация случайных паролей с использованием CSPRNG (secrets),
    оценка энтропии и копирование/сохранение результата.
  • Остальные вкладки — заглушки с планом функций.

Зависимости:
  pip install PyQt6
  # Позже для криптографии:
  # pip install cryptography pynacl
"""
from __future__ import annotations

from PyQt6 import QtCore, QtGui, QtWidgets
import secrets
import string
import math
import hashlib
import base64
import binascii
import os
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    BestAvailableEncryption,
    NoEncryption,
    load_pem_private_key,
    load_pem_public_key,
    load_der_private_key,
    load_der_public_key,
)

APP_NAME = 'ПК-К-01 "Шифроблокнот"'
APP_VERSION = '0.2.0'

# -------------------- Утилиты --------------------
AMBIGUOUS = {"l", "I", "1", "O", "0"}


def entropy_bits(charset_size: int, length: int) -> float:
    """Оценка энтропии (бит) при равновероятном выборе из алфавита.
    H = length * log2(|charset|)
    """
    if charset_size <= 1 or length <= 0:
        return 0.0
    return length * math.log2(charset_size)


def classify_strength(bits: float) -> str:
    """Базовая классификация по битам энтропии.
    Источник: эвристика; позднее можно заменить на zxcvbn‑подобную.
    """
    if bits < 28:
        return "Очень слабый"
    elif bits < 36:
        return "Слабый"
    elif bits < 60:
        return "Приемлемый"
    elif bits < 80:
        return "Сильный"
    else:
        return "Очень сильный"


def copy_to_clipboard(text: str) -> None:
    cb = QtWidgets.QApplication.clipboard()
    cb.setText(text, mode=cb.Mode.Clipboard)


# -------------------- Виджет генератора паролей --------------------
class PasswordGeneratorWidget(QtWidgets.QWidget):
    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self.init_ui()

    def init_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Группа опций
        opts = QtWidgets.QGroupBox("Опции")
        form = QtWidgets.QGridLayout(opts)

        self.length_spin = QtWidgets.QSpinBox()
        self.length_spin.setRange(4, 256)
        self.length_spin.setValue(16)
        self.length_spin.setToolTip("Длина генерируемого пароля (4–256 символов)")

        self.lower_cb = QtWidgets.QCheckBox("Строчные (a–z)")
        self.lower_cb.setChecked(True)
        self.upper_cb = QtWidgets.QCheckBox("Прописные (A–Z)")
        self.upper_cb.setChecked(True)
        self.digits_cb = QtWidgets.QCheckBox("Цифры (0–9)")
        self.digits_cb.setChecked(True)
        self.symbols_cb = QtWidgets.QCheckBox("Символы (!@#$…)")
        self.symbols_cb.setChecked(True)

        self.ambig_cb = QtWidgets.QCheckBox("Исключить похожие (l, I, 1, O, 0)")
        self.ambig_cb.setChecked(True)

        self.require_each_cb = QtWidgets.QCheckBox("Требовать хотя бы по одному из выбранных наборов")
        self.require_each_cb.setChecked(True)

        form.addWidget(QtWidgets.QLabel("Длина:"), 0, 0)
        form.addWidget(self.length_spin, 0, 1)
        form.addWidget(self.lower_cb, 1, 0)
        form.addWidget(self.upper_cb, 1, 1)
        form.addWidget(self.digits_cb, 2, 0)
        form.addWidget(self.symbols_cb, 2, 1)
        form.addWidget(self.ambig_cb, 3, 0)
        form.addWidget(self.require_each_cb, 3, 1)

        # Группа вывода
        out_box = QtWidgets.QGroupBox("Результат")
        out = QtWidgets.QGridLayout(out_box)

        self.output_edit = QtWidgets.QLineEdit()
        self.output_edit.setReadOnly(True)
        self.output_edit.setFont(QtGui.QFont("Consolas", 11))
        self.output_edit.setPlaceholderText("Здесь появится сгенерированный пароль…")

        self.entropy_label = QtWidgets.QLabel("Энтропия: 0 бит — Очень слабый")
        self.entropy_label.setStyleSheet("color: #555;")

        self.generate_btn = QtWidgets.QPushButton("Сгенерировать")
        self.copy_btn = QtWidgets.QPushButton("Копировать")
        self.save_btn = QtWidgets.QPushButton("Сохранить…")

        out.addWidget(self.output_edit, 0, 0, 1, 3)
        out.addWidget(self.entropy_label, 1, 0, 1, 3)
        out.addWidget(self.generate_btn, 2, 0)
        out.addWidget(self.copy_btn, 2, 1)
        out.addWidget(self.save_btn, 2, 2)

        # Связи
        self.generate_btn.clicked.connect(self.generate_clicked)
        self.copy_btn.clicked.connect(self.copy_clicked)
        self.save_btn.clicked.connect(self.save_clicked)

        layout.addWidget(opts)
        layout.addWidget(out_box)
        layout.addStretch(1)

        self.update_entropy_preview()

        for cb in (self.lower_cb, self.upper_cb, self.digits_cb, self.symbols_cb, self.ambig_cb):
            cb.stateChanged.connect(self.update_entropy_preview)
        self.length_spin.valueChanged.connect(self.update_entropy_preview)

    # --- Логика генерации ---
    def build_charset(self) -> str:
        chars = ""
        if self.lower_cb.isChecked():
            chars += string.ascii_lowercase
        if self.upper_cb.isChecked():
            chars += string.ascii_uppercase
        if self.digits_cb.isChecked():
            chars += string.digits
        if self.symbols_cb.isChecked():
            # Консервативный набор широко поддерживаемых символов
            chars += "!@#$%^&*()-_=+[]{};:,<.>/?"
        if self.ambig_cb.isChecked():
            chars = "".join(c for c in chars if c not in AMBIGUOUS)
        return chars

    def selected_sets_count(self) -> int:
        return sum([
            1 if self.lower_cb.isChecked() else 0,
            1 if self.upper_cb.isChecked() else 0,
            1 if self.digits_cb.isChecked() else 0,
            1 if self.symbols_cb.isChecked() else 0,
        ])

    def generate_password(self, length: int, require_each: bool) -> str:
        charset = self.build_charset()
        if len(charset) < 2:
            raise ValueError("Выберите минимум два набора символов для надёжности.")
        if not require_each:
            return "".join(secrets.choice(charset) for _ in range(length))

        # Обеспечиваем хотя бы по одному символу из каждого выбранного поднабора
        selected_sets: list[list[str]] = []
        if self.lower_cb.isChecked():
            selected_sets.append([c for c in string.ascii_lowercase if (c not in AMBIGUOUS or not self.ambig_cb.isChecked())])
        if self.upper_cb.isChecked():
            selected_sets.append([c for c in string.ascii_uppercase if (c not in AMBIGUOUS or not self.ambig_cb.isChecked())])
        if self.digits_cb.isChecked():
            selected_sets.append([c for c in string.digits if (c not in AMBIGUOUS or not self.ambig_cb.isChecked())])
        if self.symbols_cb.isChecked():
            selected_sets.append([c for c in "!@#$%^&*()-_=+[]{};:,<.>/?"])

        if length < len(selected_sets):
            raise ValueError(f"Длина должна быть не меньше {len(selected_sets)}, чтобы включить все выбранные наборы.")

        pwd_chars = [secrets.choice(s) for s in selected_sets]
        remaining = length - len(pwd_chars)
        charset_list = list(charset)
        pwd_chars += [secrets.choice(charset_list) for _ in range(remaining)]
        # Перемешивание Фишера–Йетса на CSPRNG
        for i in range(len(pwd_chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            pwd_chars[i], pwd_chars[j] = pwd_chars[j], pwd_chars[i]
        return "".join(pwd_chars)

    def update_entropy_preview(self) -> None:
        length = self.length_spin.value()
        charset = self.build_charset()
        bits = entropy_bits(len(charset), length)
        base = classify_strength(bits)

        # Правило «разнообразия»: если выбран 1 набор, понижаем оценку на 2 уровня,
        # если 2 набора — на 1 уровень. Так мы сигналим, что однообразные пароли
        # хуже проходят реальные политики и атакующие легче их брутят.
        levels = ["Очень слабый", "Слабый", "Приемлемый", "Сильный", "Очень сильный"]
        idx = levels.index(base)
        sets = self.selected_sets_count()
        penalty = 2 if sets == 1 else (1 if sets == 2 else 0)
        idx = max(0, idx - penalty)
        label = levels[idx]

        suffix = ""
        if sets == 1:
            suffix = "  • предупреждение: используется только один тип символов"
        elif sets == 2:
            suffix = "  • совет: добавьте ещё тип символов для стойкости"

        self.entropy_label.setText(f"Энтропия: {bits:.1f} бит (оценка: {label}){suffix}")

    # --- Обработчики ---
    def generate_clicked(self) -> None:
        try:
            length = self.length_spin.value()
            require_each = self.require_each_cb.isChecked()
            pwd = self.generate_password(length, require_each)
            self.output_edit.setText(pwd)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Ошибка генерации", str(e))

    def copy_clicked(self) -> None:
        text = self.output_edit.text()
        if not text:
            return
        copy_to_clipboard(text)
        QtWidgets.QToolTip.showText(self.mapToGlobal(QtCore.QPoint(0, 0)), "Скопировано в буфер")

    def save_clicked(self) -> None:
        text = self.output_edit.text()
        if not text:
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Сохранить пароль", "", "Текстовые файлы (*.txt);;Все файлы (*)")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text + "\n")
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Ошибка сохранения", str(e))


# -------------------- Заглушки вкладок --------------------
class Placeholder(QtWidgets.QWidget):
    def __init__(self, title: str, description: str, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        lbl = QtWidgets.QLabel(f"<h3>{title}</h3><p>{description}</p>")
        lbl.setWordWrap(True)
        layout.addWidget(lbl)
        layout.addStretch(1)


# -------------------- Виджет хеширования --------------------
class HashWidget(QtWidgets.QWidget):
    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self._last_source_kind = "text"  # or "file"
        self.init_ui()

    def init_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Источник данных
        src_box = QtWidgets.QGroupBox("Источник")
        src = QtWidgets.QGridLayout(src_box)

        self.input_edit = QtWidgets.QPlainTextEdit()
        self.input_edit.setPlaceholderText("Введите текст для хеширования или выберите файл ниже…")
        self.input_edit.setTabChangesFocus(True)
        self.input_edit.textChanged.connect(self.compute_hashes)

        file_row = QtWidgets.QHBoxLayout()
        self.file_path_edit = QtWidgets.QLineEdit()
        self.file_path_edit.setReadOnly(True)
        self.file_path_edit.setPlaceholderText("Файл не выбран")
        btn_browse = QtWidgets.QPushButton("Открыть…")
        btn_clear = QtWidgets.QPushButton("Очистить")
        btn_browse.clicked.connect(self.browse_file)
        btn_clear.clicked.connect(self.clear_file)
        file_row.addWidget(QtWidgets.QLabel("Файл:"))
        file_row.addWidget(self.file_path_edit, 1)
        file_row.addWidget(btn_browse)
        file_row.addWidget(btn_clear)

        # Алгоритмы
        algo_row = QtWidgets.QHBoxLayout()
        algo_row.addWidget(QtWidgets.QLabel("Алгоритмы:"))
        self.sha256_cb = QtWidgets.QCheckBox("SHA-256")
        self.sha3_cb = QtWidgets.QCheckBox("SHA3-256")
        self.blake2b_cb = QtWidgets.QCheckBox("BLAKE2b")
        for cb in (self.sha256_cb, self.sha3_cb, self.blake2b_cb):
            cb.setChecked(True)
            cb.stateChanged.connect(self.compute_hashes)
        algo_row.addWidget(self.sha256_cb)
        algo_row.addWidget(self.sha3_cb)
        algo_row.addWidget(self.blake2b_cb)
        algo_row.addStretch(1)

        src.addWidget(self.input_edit, 0, 0, 1, 1)
        src.addLayout(file_row, 1, 0)
        src.addLayout(algo_row, 2, 0)

        # Результаты
        out_box = QtWidgets.QGroupBox("Хеши")
        out = QtWidgets.QGridLayout(out_box)
        self.info_label = QtWidgets.QLabel("Готово")
        self.info_label.setStyleSheet("color: #555;")

        self.sha256_out = QtWidgets.QLineEdit(); self.sha256_out.setReadOnly(True); self.sha256_out.setFont(QtGui.QFont("Consolas", 10))
        self.sha3_out = QtWidgets.QLineEdit(); self.sha3_out.setReadOnly(True); self.sha3_out.setFont(QtGui.QFont("Consolas", 10))
        self.blake2b_out = QtWidgets.QLineEdit(); self.blake2b_out.setReadOnly(True); self.blake2b_out.setFont(QtGui.QFont("Consolas", 10))

        def mk_copy_btn(target: QtWidgets.QLineEdit) -> QtWidgets.QPushButton:
            b = QtWidgets.QPushButton("Копировать")
            b.clicked.connect(lambda: copy_to_clipboard(target.text()))
            return b

        row = 0
        out.addWidget(self.info_label, row, 0, 1, 3); row += 1
        out.addWidget(QtWidgets.QLabel("SHA-256:"), row, 0)
        out.addWidget(self.sha256_out, row, 1)
        out.addWidget(mk_copy_btn(self.sha256_out), row, 2); row += 1
        out.addWidget(QtWidgets.QLabel("SHA3-256:"), row, 0)
        out.addWidget(self.sha3_out, row, 1)
        out.addWidget(mk_copy_btn(self.sha3_out), row, 2); row += 1
        out.addWidget(QtWidgets.QLabel("BLAKE2b:"), row, 0)
        out.addWidget(self.blake2b_out, row, 1)
        out.addWidget(mk_copy_btn(self.blake2b_out), row, 2); row += 1

        btns = QtWidgets.QHBoxLayout()
        self.compute_btn = QtWidgets.QPushButton("Пересчитать")
        self.compute_btn.clicked.connect(self.compute_hashes)
        self.copy_all_btn = QtWidgets.QPushButton("Копировать всё")
        self.copy_all_btn.clicked.connect(self.copy_all)
        self.save_btn = QtWidgets.QPushButton("Сохранить…")
        self.save_btn.clicked.connect(self.save_results)
        btns.addWidget(self.compute_btn)
        btns.addWidget(self.copy_all_btn)
        btns.addWidget(self.save_btn)
        btns.addStretch(1)

        out.addLayout(btns, row, 0, 1, 3)

        layout.addWidget(src_box)
        layout.addWidget(out_box)
        layout.addStretch(1)

        # Drag&drop файла на виджет
        self.setAcceptDrops(True)
        self.compute_hashes()

    # Drag and drop support
    def dragEnterEvent(self, event: QtGui.QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QtGui.QDropEvent) -> None:
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if os.path.isfile(path):
                self.file_path_edit.setText(path)
                self._last_source_kind = "file"
                self.compute_hashes()
                break

    def browse_file(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Выбрать файл для хеширования", "", "Все файлы (*)")
        if path:
            self.file_path_edit.setText(path)
            self._last_source_kind = "file"
            self.compute_hashes()

    def clear_file(self) -> None:
        self.file_path_edit.clear()
        self._last_source_kind = "text"
        self.compute_hashes()

    def selected_algorithms(self) -> list[str]:
        algos: list[str] = []
        if self.sha256_cb.isChecked():
            algos.append("sha256")
        if self.sha3_cb.isChecked():
            algos.append("sha3_256")
        if self.blake2b_cb.isChecked():
            algos.append("blake2b")
        return algos

    def compute_hashes(self) -> None:
        algos = self.selected_algorithms()
        if not algos:
            self.info_label.setText("Выберите хотя бы один алгоритм")
            self.sha256_out.clear(); self.sha3_out.clear(); self.blake2b_out.clear()
            return

        # Подготовка хеш-объектов
        h = {}
        for a in algos:
            if a == "sha256":
                h[a] = hashlib.sha256()
            elif a == "sha3_256":
                h[a] = hashlib.sha3_256()
            elif a == "blake2b":
                h[a] = hashlib.blake2b()

        file_path = self.file_path_edit.text().strip()
        try:
            if file_path and os.path.isfile(file_path):
                total = 0
                with open(file_path, "rb") as f:
                    while True:
                        chunk = f.read(1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        for obj in h.values():
                            obj.update(chunk)
                self._last_source_kind = "file"
                self.info_label.setText(f"Файл: {os.path.basename(file_path)} — {total} байт")
            else:
                data = self.input_edit.toPlainText().encode("utf-8")
                for obj in h.values():
                    obj.update(data)
                self._last_source_kind = "text"
                self.info_label.setText(f"Текст: {len(data)} байт (UTF-8)")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Ошибка хеширования", str(e))
            return

        # Вывод
        self.sha256_out.setText(h.get("sha256").hexdigest() if h.get("sha256") else "")
        self.sha3_out.setText(h.get("sha3_256").hexdigest() if h.get("sha3_256") else "")
        self.blake2b_out.setText(h.get("blake2b").hexdigest() if h.get("blake2b") else "")

    def copy_all(self) -> None:
        lines = []
        if self.sha256_cb.isChecked() and self.sha256_out.text():
            lines.append(f"SHA-256  {self.sha256_out.text()}")
        if self.sha3_cb.isChecked() and self.sha3_out.text():
            lines.append(f"SHA3-256 {self.sha3_out.text()}")
        if self.blake2b_cb.isChecked() and self.blake2b_out.text():
            lines.append(f"BLAKE2b  {self.blake2b_out.text()}")
        copy_to_clipboard("\n".join(lines))
        QtWidgets.QToolTip.showText(self.mapToGlobal(QtCore.QPoint(0, 0)), "Хеши скопированы")

    def save_results(self) -> None:
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Сохранить хеши", "", "Текстовые файлы (*.txt);;Все файлы (*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                if self._last_source_kind == "file" and self.file_path_edit.text():
                    f.write(f"Файл: {self.file_path_edit.text()}\n")
                f.write("Алгоритмы и хеши:\n")
                if self.sha256_cb.isChecked() and self.sha256_out.text():
                    f.write(f"SHA-256:  {self.sha256_out.text()}\n")
                if self.sha3_cb.isChecked() and self.sha3_out.text():
                    f.write(f"SHA3-256: {self.sha3_out.text()}\n")
                if self.blake2b_cb.isChecked() and self.blake2b_out.text():
                    f.write(f"BLAKE2b:  {self.blake2b_out.text()}\n")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Ошибка сохранения", str(e))


# -------------------- Виджет кодирования --------------------
class CodecWidget(QtWidgets.QWidget):
    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self._last_raw_bytes: bytes | None = None
        self.init_ui()

    def init_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        ctrls = QtWidgets.QHBoxLayout()
        self.b64_enc_btn = QtWidgets.QPushButton("Base64: кодировать")
        self.b64_dec_btn = QtWidgets.QPushButton("Base64: декодировать")
        self.hex_enc_btn = QtWidgets.QPushButton("Hex: кодировать")
        self.hex_dec_btn = QtWidgets.QPushButton("Hex: декодировать")
        for b in (self.b64_enc_btn, self.b64_dec_btn, self.hex_enc_btn, self.hex_dec_btn):
            ctrls.addWidget(b)
        ctrls.addStretch(1)

        io = QtWidgets.QGridLayout()
        self.input_edit = QtWidgets.QPlainTextEdit()
        self.input_edit.setPlaceholderText("Входные данные (текст). Для бинарных файлов используйте кодирование из файла в разделе хешей или вставьте base64/hex.")
        self.output_edit = QtWidgets.QPlainTextEdit()
        self.output_edit.setReadOnly(False)
        self.output_edit.setPlaceholderText("Результат…")
        mono = QtGui.QFont("Consolas", 10)
        self.input_edit.setFont(mono)
        self.output_edit.setFont(mono)

        io.addWidget(QtWidgets.QLabel("Вход"), 0, 0)
        io.addWidget(QtWidgets.QLabel("Выход"), 0, 1)
        io.addWidget(self.input_edit, 1, 0)
        io.addWidget(self.output_edit, 1, 1)

        actions = QtWidgets.QHBoxLayout()
        self.copy_out_btn = QtWidgets.QPushButton("Копировать выход")
        self.save_out_btn = QtWidgets.QPushButton("Сохранить выход…")
        actions.addWidget(self.copy_out_btn)
        actions.addWidget(self.save_out_btn)
        actions.addStretch(1)

        self.info_label = QtWidgets.QLabel("")
        self.info_label.setStyleSheet("color:#555;")

        layout.addLayout(ctrls)
        layout.addLayout(io)
        layout.addLayout(actions)
        layout.addWidget(self.info_label)
        layout.addStretch(1)

        # Signals
        self.b64_enc_btn.clicked.connect(self.b64_encode)
        self.b64_dec_btn.clicked.connect(self.b64_decode)
        self.hex_enc_btn.clicked.connect(self.hex_encode)
        self.hex_dec_btn.clicked.connect(self.hex_decode)
        self.copy_out_btn.clicked.connect(lambda: copy_to_clipboard(self.output_edit.toPlainText()))
        self.save_out_btn.clicked.connect(self.save_output)

    def b64_encode(self) -> None:
        data = self.input_edit.toPlainText().encode("utf-8")
        out = base64.b64encode(data).decode("ascii")
        self._last_raw_bytes = None
        self.output_edit.setPlainText(out)
        self.info_label.setText(f"Base64 кодировано: вход {len(data)} байт → выход {len(out)} символов")

    def b64_decode(self) -> None:
        text = self.input_edit.toPlainText().strip()
        try:
            raw = base64.b64decode(text, validate=True)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Ошибка Base64", f"Неверные данные: {e}")
            return
        self._last_raw_bytes = raw
        try:
            out_text = raw.decode("utf-8")
            self.output_edit.setPlainText(out_text)
            self.info_label.setText(f"Base64 декодировано: {len(raw)} байт; показан UTF-8 текст")
        except UnicodeDecodeError:
            self.output_edit.setPlainText("[Бинарные данные: сохраните в файл]")
            self.info_label.setText(f"Base64 декодировано: {len(raw)} байт бинарных данных")

    def hex_encode(self) -> None:
        data = self.input_edit.toPlainText().encode("utf-8")
        out = binascii.hexlify(data).decode("ascii")
        self._last_raw_bytes = None
        self.output_edit.setPlainText(out)
        self.info_label.setText(f"Hex кодировано: вход {len(data)} байт → выход {len(out)} символов")

    def hex_decode(self) -> None:
        text = self.input_edit.toPlainText().strip().replace(" ", "").lower()
        try:
            raw = binascii.unhexlify(text)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Ошибка Hex", f"Неверные данные: {e}")
            return
        self._last_raw_bytes = raw
        try:
            out_text = raw.decode("utf-8")
            self.output_edit.setPlainText(out_text)
            self.info_label.setText(f"Hex декодировано: {len(raw)} байт; показан UTF-8 текст")
        except UnicodeDecodeError:
            self.output_edit.setPlainText("[Бинарные данные: сохраните в файл]")
            self.info_label.setText(f"Hex декодировано: {len(raw)} байт бинарных данных")

    def save_output(self) -> None:
        # Если последний результат был бинарным (декодирование), сохраняем в двоичном виде.
        if self._last_raw_bytes is not None:
            path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Сохранить бинарные данные", "", "Все файлы (*)")
            if not path:
                return
            try:
                with open(path, "wb") as f:
                    f.write(self._last_raw_bytes)
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Ошибка сохранения", str(e))
            return
        # Иначе сохраняем текст из правой панели
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Сохранить текст", "", "Текстовые файлы (*.txt);;Все файлы (*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.output_edit.toPlainText())
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Ошибка сохранения", str(e))


# -------------------- AES-GCM шифрование --------------------
class AESGcmWidget(QtWidgets.QWidget):
    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self.init_ui()

    def init_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        top = QtWidgets.QGridLayout()
        row = 0
        top.addWidget(QtWidgets.QLabel("Режим:"), row, 0)
        self.mode_cb = QtWidgets.QComboBox()
        self.mode_cb.addItems(["Зашифровать", "Расшифровать"])
        top.addWidget(self.mode_cb, row, 1); row += 1

        top.addWidget(QtWidgets.QLabel("Ключ:"), row, 0)
        self.key_src_cb = QtWidgets.QComboBox()
        self.key_src_cb.addItems([
            "Пароль (Scrypt)",
            "Пароль (PBKDF2-HMAC-SHA256)",
            "Сырой ключ (hex/base64)",
        ])
        top.addWidget(self.key_src_cb, row, 1); row += 1

        # Пароль
        self.pass_edit = QtWidgets.QLineEdit(); self.pass_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.pass_edit.setPlaceholderText("Пароль…")
        self.show_pass_btn = QtWidgets.QPushButton("Показать")
        self.show_pass_btn.setCheckable(True)
        self.show_pass_btn.toggled.connect(lambda on: self.pass_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal if on else QtWidgets.QLineEdit.EchoMode.Password))
        pass_row = QtWidgets.QHBoxLayout(); pass_row.addWidget(self.pass_edit, 1); pass_row.addWidget(self.show_pass_btn)
        top.addWidget(QtWidgets.QLabel("Пароль:"), row, 0)
        top.addLayout(pass_row, row, 1); row += 1

        # Соль
        self.salt_edit = QtWidgets.QLineEdit(); self.salt_edit.setPlaceholderText("Соль (hex), по умолчанию будет сгенерирована")
        self.gen_salt_btn = QtWidgets.QPushButton("Сгенерировать соль")
        self.gen_salt_btn.clicked.connect(self.generate_salt)
        salt_row = QtWidgets.QHBoxLayout(); salt_row.addWidget(self.salt_edit, 1); salt_row.addWidget(self.gen_salt_btn)
        top.addWidget(QtWidgets.QLabel("Соль:"), row, 0)
        top.addLayout(salt_row, row, 1); row += 1

        # Сырой ключ
        self.raw_key_edit = QtWidgets.QLineEdit(); self.raw_key_edit.setPlaceholderText("Ключ 32 байта (hex/base64)")
        top.addWidget(QtWidgets.QLabel("Сырой ключ:"), row, 0)
        top.addWidget(self.raw_key_edit, row, 1); row += 1

        # Nonce
        self.nonce_edit = QtWidgets.QLineEdit(); self.nonce_edit.setPlaceholderText("Nonce 12 байт (hex), по умолчанию будет сгенерирован")
        self.gen_nonce_btn = QtWidgets.QPushButton("Сгенерировать nonce")
        self.gen_nonce_btn.clicked.connect(self.generate_nonce)
        nonce_row = QtWidgets.QHBoxLayout(); nonce_row.addWidget(self.nonce_edit, 1); nonce_row.addWidget(self.gen_nonce_btn)
        top.addWidget(QtWidgets.QLabel("Nonce:"), row, 0)
        top.addLayout(nonce_row, row, 1); row += 1

        # AAD
        self.aad_edit = QtWidgets.QLineEdit(); self.aad_edit.setPlaceholderText("AAD (необязательно, текст будет закодирован как UTF-8)")
        top.addWidget(QtWidgets.QLabel("AAD:"), row, 0)
        top.addWidget(self.aad_edit, row, 1); row += 1

        layout.addLayout(top)

        io = QtWidgets.QGridLayout()
        self.input_edit = QtWidgets.QPlainTextEdit(); self.input_edit.setFont(QtGui.QFont("Consolas", 10))
        self.output_edit = QtWidgets.QPlainTextEdit(); self.output_edit.setFont(QtGui.QFont("Consolas", 10))
        self.input_edit.setPlaceholderText("Входные данные (текст для шифрования или JSON-контейнер для расшифровки)…")
        self.output_edit.setPlaceholderText("Результат…")
        io.addWidget(QtWidgets.QLabel("Вход"), 0, 0)
        io.addWidget(QtWidgets.QLabel("Выход"), 0, 1)
        io.addWidget(self.input_edit, 1, 0)
        io.addWidget(self.output_edit, 1, 1)
        layout.addLayout(io)

        actions = QtWidgets.QHBoxLayout()
        self.exec_btn = QtWidgets.QPushButton("Выполнить")
        self.copy_btn = QtWidgets.QPushButton("Копировать результат")
        self.save_text_btn = QtWidgets.QPushButton("Сохранить текст…")
        self.load_file_btn = QtWidgets.QPushButton("Загрузить файл как вход…")
        self.save_file_btn = QtWidgets.QPushButton("Сохранить выход в файл…")
        actions.addWidget(self.exec_btn)
        actions.addWidget(self.copy_btn)
        actions.addWidget(self.save_text_btn)
        actions.addWidget(self.load_file_btn)
        actions.addWidget(self.save_file_btn)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.info_label = QtWidgets.QLabel("")
        self.info_label.setStyleSheet("color:#555;")
        layout.addWidget(self.info_label)
        layout.addStretch(1)

        # Signals
        self.key_src_cb.currentIndexChanged.connect(self.update_key_visibility)
        self.exec_btn.clicked.connect(self.execute)
        self.copy_btn.clicked.connect(lambda: copy_to_clipboard(self.output_edit.toPlainText()))
        self.save_text_btn.clicked.connect(self.save_text_output)
        self.load_file_btn.clicked.connect(self.load_file_as_input)
        self.save_file_btn.clicked.connect(self.save_output_to_file)

        self.update_key_visibility()

    def update_key_visibility(self) -> None:
        src = self.key_src_cb.currentText()
        pw = "Пароль" in src
        self.pass_edit.setEnabled(pw)
        self.gen_salt_btn.setEnabled(pw)
        self.salt_edit.setEnabled(pw)
        self.raw_key_edit.setEnabled(not pw)

    def generate_salt(self) -> None:
        self.salt_edit.setText(os.urandom(16).hex())

    def generate_nonce(self) -> None:
        self.nonce_edit.setText(os.urandom(12).hex())

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        src = self.key_src_cb.currentText()
        if src.startswith("Пароль (Scrypt)"):
            kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
            return kdf.derive(password.encode("utf-8"))
        elif src.startswith("Пароль (PBKDF2"):
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
            return kdf.derive(password.encode("utf-8"))
        else:
            raise ValueError("Неверный источник ключа для KDF")

    def _get_key(self) -> tuple[bytes, dict]:
        src = self.key_src_cb.currentText()
        meta = {}
        if src.startswith("Пароль"):
            pwd = self.pass_edit.text()
            if not pwd:
                raise ValueError("Введите пароль")
            salt_hex = self.salt_edit.text().strip()
            if salt_hex:
                try:
                    salt = bytes.fromhex(salt_hex)
                except Exception:
                    raise ValueError("Соль должна быть в hex")
            else:
                salt = os.urandom(16)
                self.salt_edit.setText(salt.hex())
            key = self._derive_key(pwd, salt)
            meta["kdf"] = "scrypt" if src.startswith("Пароль (Scrypt)") else "pbkdf2"
            meta["salt"] = base64.b64encode(salt).decode("ascii")
            return key, meta
        else:
            val = self.raw_key_edit.text().strip()
            if not val:
                raise ValueError("Введите сырой ключ (hex/base64)")
            try:
                if all(c in "0123456789abcdefABCDEF" for c in val) and len(val) >= 64:
                    key = bytes.fromhex(val)
                else:
                    key = base64.b64decode(val, validate=True)
            except Exception:
                raise ValueError("Ключ должен быть hex или base64")
            if len(key) != 32:
                raise ValueError("Ключ должен быть 32 байта (AES-256)")
            meta["kdf"] = "raw"
            return key, meta

    def _get_nonce(self) -> bytes:
        txt = self.nonce_edit.text().strip()
        if txt:
            try:
                n = bytes.fromhex(txt)
            except Exception:
                raise ValueError("Nonce должен быть hex")
            if len(n) != 12:
                raise ValueError("Nonce должен быть 12 байт")
            return n
        n = os.urandom(12)
        self.nonce_edit.setText(n.hex())
        return n

    def execute(self) -> None:
        try:
            mode = self.mode_cb.currentText()
            aad = self.aad_edit.text().encode("utf-8") if self.aad_edit.text() else None
            if mode == "Зашифровать":
                key, meta = self._get_key()
                nonce = self._get_nonce()
                data = self.input_edit.toPlainText().encode("utf-8")
                ct = AESGCM(key).encrypt(nonce, data, aad)
                obj = {
                    "v": 1,
                    "alg": "AES-256-GCM",
                    "kdf": meta.get("kdf"),
                    "salt": meta.get("salt"),
                    "nonce": base64.b64encode(nonce).decode("ascii"),
                    "aad": base64.b64encode(aad).decode("ascii") if aad else None,
                    "ct": base64.b64encode(ct).decode("ascii"),
                }
                out = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
                self.output_edit.setPlainText(out)
                self.info_label.setText(f"Зашифровано: вход {len(data)} байт → выход {len(out)} символов JSON")
            else:
                text = self.input_edit.toPlainText().strip()
                try:
                    obj = json.loads(text)
                except Exception:
                    QtWidgets.QMessageBox.warning(self, "Ошибка", "Ожидался JSON-контейнер")
                    return
                kdf_name = obj.get("kdf")
                if kdf_name in ("scrypt", "pbkdf2"):
                    pwd = self.pass_edit.text()
                    if not pwd:
                        raise ValueError("Для расшифровки по паролю введите пароль")
                    salt_b64 = obj.get("salt")
                    if not salt_b64:
                        raise ValueError("В контейнере отсутствует соль")
                    salt = base64.b64decode(salt_b64)
                    if kdf_name == "scrypt":
                        key = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(pwd.encode("utf-8"))
                    else:
                        key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000).derive(pwd.encode("utf-8"))
                elif kdf_name == "raw":
                    key, _ = self._get_key()
                else:
                    raise ValueError("Неизвестный тип kdf в контейнере")
                nonce = base64.b64decode(obj["nonce"]) if obj.get("nonce") else None
                aad_b = base64.b64decode(obj["aad"]) if obj.get("aad") else None
                ct = base64.b64decode(obj["ct"]) if obj.get("ct") else b""
                pt = AESGCM(key).decrypt(nonce, ct, aad_b)
                try:
                    out_text = pt.decode("utf-8")
                    self.output_edit.setPlainText(out_text)
                    self.info_label.setText(f"Расшифровано: {len(pt)} байт; показан UTF-8 текст")
                except UnicodeDecodeError:
                    self.output_edit.setPlainText("[Бинарные данные: сохраните в файл]")
                    self._last_binary = pt
                    self.info_label.setText(f"Расшифровано: {len(pt)} байт бинарных данных")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Ошибка", str(e))

    def save_text_output(self) -> None:
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Сохранить текст", "", "Текстовые файлы (*.txt);;Все файлы (*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.output_edit.toPlainText())
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Ошибка сохранения", str(e))

    def load_file_as_input(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Выбрать файл", "", "Все файлы (*)")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            # Помещаем как текст (если это JSON), иначе как base64
            try:
                txt = data.decode("utf-8")
                self.input_edit.setPlainText(txt)
                self.info_label.setText(f"Загружено из файла: {len(data)} байт (UTF-8)")
            except UnicodeDecodeError:
                self.input_edit.setPlainText(base64.b64encode(data).decode("ascii"))
                self.info_label.setText(f"Загружено из файла: {len(data)} байт; показан base64")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Ошибка чтения", str(e))

    def save_output_to_file(self) -> None:
        # Если в выходе отмечены бинарные данные из расшифровки
        if getattr(self, "_last_binary", None):
            path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Сохранить бинарные данные", "", "Все файлы (*)")
            if not path:
                return
            try:
                with open(path, "wb") as f:
                    f.write(self._last_binary)
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Ошибка сохранения", str(e))
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Сохранить текст", "", "Текстовые файлы (*.txt);;Все файлы (*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.output_edit.toPlainText())
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Ошибка сохранения", str(e))


# -------------------- Управление ключами (RSA / Ed25519) --------------------
class KeysWidget(QtWidgets.QWidget):
    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self.current_private = None
        self.current_public = None
        self.init_ui()

    def init_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Генерация/импорт
        box = QtWidgets.QGroupBox("Ключи")
        grid = QtWidgets.QGridLayout(box)
        row = 0
        grid.addWidget(QtWidgets.QLabel("Тип:"), row, 0)
        self.type_cb = QtWidgets.QComboBox(); self.type_cb.addItems(["RSA", "Ed25519"]) ; grid.addWidget(self.type_cb, row, 1); row += 1
        grid.addWidget(QtWidgets.QLabel("RSA размер:"), row, 0)
        self.rsa_bits_cb = QtWidgets.QComboBox(); self.rsa_bits_cb.addItems(["2048", "3072", "4096"]) ; grid.addWidget(self.rsa_bits_cb, row, 1); row += 1

        btns = QtWidgets.QHBoxLayout()
        self.gen_btn = QtWidgets.QPushButton("Сгенерировать")
        self.import_btn = QtWidgets.QPushButton("Импорт…")
        self.export_priv_btn = QtWidgets.QPushButton("Экспорт приватного…")
        self.export_pub_btn = QtWidgets.QPushButton("Экспорт публичного…")
        btns.addWidget(self.gen_btn)
        btns.addWidget(self.import_btn)
        btns.addWidget(self.export_priv_btn)
        btns.addWidget(self.export_pub_btn)
        btns.addStretch(1)
        grid.addLayout(btns, row, 0, 1, 2); row += 1

        self.protect_cb = QtWidgets.QCheckBox("Шифровать приватный PEM паролем")
        self.protect_pass = QtWidgets.QLineEdit(); self.protect_pass.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        pass_row = QtWidgets.QHBoxLayout(); pass_row.addWidget(self.protect_cb); pass_row.addWidget(self.protect_pass)
        grid.addLayout(pass_row, row, 0, 1, 2); row += 1

        self.fp_label = QtWidgets.QLabel("Отпечаток: —")
        grid.addWidget(self.fp_label, row, 0, 1, 2); row += 1

        layout.addWidget(box)

        # Подпись/проверка
        sign_box = QtWidgets.QGroupBox("Подпись / Проверка")
        sgrid = QtWidgets.QGridLayout(sign_box)
        sgrid.addWidget(QtWidgets.QLabel("Сообщение"), 0, 0)
        sgrid.addWidget(QtWidgets.QLabel("Подпись (Base64)"), 0, 1)
        self.msg_edit = QtWidgets.QPlainTextEdit(); self.msg_edit.setFont(QtGui.QFont("Consolas", 10))
        self.sig_edit = QtWidgets.QPlainTextEdit(); self.sig_edit.setFont(QtGui.QFont("Consolas", 10))
        sgrid.addWidget(self.msg_edit, 1, 0)
        sgrid.addWidget(self.sig_edit, 1, 1)

        sbtns = QtWidgets.QHBoxLayout()
        self.sign_btn = QtWidgets.QPushButton("Подписать")
        self.verify_btn = QtWidgets.QPushButton("Проверить")
        sbtns.addWidget(self.sign_btn)
        sbtns.addWidget(self.verify_btn)
        sbtns.addStretch(1)
        sgrid.addLayout(sbtns, 2, 0, 1, 2)

        layout.addWidget(sign_box)
        layout.addStretch(1)

        # Signals
        self.type_cb.currentIndexChanged.connect(self._on_type_changed)
        self.gen_btn.clicked.connect(self.generate_key)
        self.import_btn.clicked.connect(self.import_key)
        self.export_priv_btn.clicked.connect(self.export_private)
        self.export_pub_btn.clicked.connect(self.export_public)
        self.sign_btn.clicked.connect(self.sign_message)
        self.verify_btn.clicked.connect(self.verify_signature)

        self._on_type_changed()

    def _on_type_changed(self) -> None:
        is_rsa = self.type_cb.currentText() == "RSA"
        self.rsa_bits_cb.setEnabled(is_rsa)

    def _update_fingerprint(self) -> None:
        if not self.current_public:
            self.fp_label.setText("Отпечаток: —")
            return
        pub_bytes = self.current_public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        fp = hashlib.sha256(pub_bytes).digest()
        self.fp_label.setText(f"Отпечаток (SHA-256/SPKI): {base64.b64encode(fp).decode('ascii')}")

    def generate_key(self) -> None:
        try:
            if self.type_cb.currentText() == "RSA":
                bits = int(self.rsa_bits_cb.currentText())
                self.current_private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
                self.current_public = self.current_private.public_key()
            else:
                self.current_private = ed25519.Ed25519PrivateKey.generate()
                self.current_public = self.current_private.public_key()
            self._update_fingerprint()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Ошибка генерации", str(e))

    def import_key(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Импорт PEM/DER", "", "Ключи (*.pem *.der);;Все файлы (*)")
        if not path:
            return
        data = None
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Ошибка чтения", str(e)); return
        # Попробуем загрузить
        priv = pub = None
        try:
            try:
                priv = load_pem_private_key(data, password=None)
            except TypeError:
                # возможно, зашифрованный
                pwd, ok = QtWidgets.QInputDialog.getText(self, "Пароль", "Пароль для приватного ключа:", QtWidgets.QLineEdit.EchoMode.Password)
                if ok:
                    priv = load_pem_private_key(data, password=pwd.encode("utf-8"))
            except ValueError:
                pass
            if not priv:
                try:
                    pub = load_pem_public_key(data)
                except ValueError:
                    pass
            if not priv and not pub:
                try:
                    priv = load_der_private_key(data, password=None)
                except ValueError:
                    try:
                        pub = load_der_public_key(data)
                    except ValueError:
                        pass
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Ошибка импорта", str(e)); return

        if priv is None and pub is None:
            QtWidgets.QMessageBox.warning(self, "Импорт", "Не удалось распознать ключ")
            return
        if priv is not None:
            self.current_private = priv
            self.current_public = priv.public_key()
        else:
            self.current_private = None
            self.current_public = pub
        self._update_fingerprint()

    def export_private(self) -> None:
        if not self.current_private:
            QtWidgets.QMessageBox.warning(self, "Экспорт", "Приватный ключ не загружен")
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Экспорт приватного PEM", "", "PEM файлы (*.pem);;Все файлы (*)")
        if not path:
            return
        try:
            if self.protect_cb.isChecked() and self.protect_pass.text():
                enc = BestAvailableEncryption(self.protect_pass.text().encode("utf-8"))
            else:
                enc = NoEncryption()
            pem = self.current_private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, enc)
            with open(path, "wb") as f:
                f.write(pem)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Ошибка экспорта", str(e))

    def export_public(self) -> None:
        if not self.current_public:
            QtWidgets.QMessageBox.warning(self, "Экспорт", "Публичный ключ не загружен")
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Экспорт публичного PEM", "", "PEM файлы (*.pem);;Все файлы (*)")
        if not path:
            return
        try:
            pem = self.current_public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            with open(path, "wb") as f:
                f.write(pem)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Ошибка экспорта", str(e))

    def sign_message(self) -> None:
        if not self.current_private:
            QtWidgets.QMessageBox.warning(self, "Подпись", "Загрузите приватный ключ")
            return
        msg = self.msg_edit.toPlainText().encode("utf-8")
        try:
            if isinstance(self.current_private, rsa.RSAPrivateKey):
                sig = self.current_private.sign(
                    msg,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256(),
                )
            else:
                sig = self.current_private.sign(msg)
            self.sig_edit.setPlainText(base64.b64encode(sig).decode("ascii"))
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Ошибка подписи", str(e))

    def verify_signature(self) -> None:
        if not self.current_public:
            QtWidgets.QMessageBox.warning(self, "Проверка", "Загрузите публичный или приватный ключ")
            return
        msg = self.msg_edit.toPlainText().encode("utf-8")
        try:
            sig = base64.b64decode(self.sig_edit.toPlainText().strip(), validate=True)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Проверка", f"Неверная подпись (Base64): {e}")
            return
        try:
            if isinstance(self.current_public, rsa.RSAPublicKey):
                self.current_public.verify(
                    sig,
                    msg,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256(),
                )
            else:
                self.current_public.verify(sig, msg)
            QtWidgets.QMessageBox.information(self, "Проверка", "Подпись верна")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Проверка", f"Подпись НЕверна: {e}")


# -------------------- Главное окно --------------------
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.resize(980, 640)
        self.init_ui()

    def init_ui(self) -> None:
        tabs = QtWidgets.QTabWidget()
        tabs.setTabPosition(QtWidgets.QTabWidget.TabPosition.North)

        tabs.addTab(PasswordGeneratorWidget(), "Пароли")
        tabs.addTab(AESGcmWidget(), "Шифрование")
        tabs.addTab(HashWidget(), "Хеши")
        tabs.addTab(KeysWidget(), "Ключи")
        tabs.addTab(CodecWidget(), "Кодеки")

        self.setCentralWidget(tabs)

        # Меню
        menubar = self.menuBar()
        file_menu = menubar.addMenu("&Файл")
        act_quit = QtGui.QAction("Выход", self, shortcut="Ctrl+Q", triggered=self.close)
        file_menu.addAction(act_quit)

        help_menu = menubar.addMenu("&Справка")
        act_about = QtGui.QAction("О программе", self, triggered=self.show_about)
        help_menu.addAction(act_about)

    def show_about(self) -> None:
        QtWidgets.QMessageBox.information(
            self,
            "О программе",
            (
                f"{APP_NAME} v{APP_VERSION}\n\n"
                "Компактный крипто‑инструментарий (MVP).\n\n"
                "Реализовано: генератор паролей, хеширование, кодеки, AES-GCM, ключи RSA/Ed25519.\n"
                "План: расширение функций шифрования файлов и форматов контейнеров.\n\n"
                "Безопасность: случайность на базе secrets (OS CSPRNG)."
            ),
        )


# -------------------- Точка входа --------------------
def main() -> None:
    import sys
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("ПК-К")
    app.setApplicationVersion(APP_VERSION)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
