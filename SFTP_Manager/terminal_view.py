"""SSH terminal screen and keyboard bridge for the Remote Console."""

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QKeyEvent, QTextCursor, QColor
from PySide6.QtWidgets import QPlainTextEdit, QTextEdit
import pyte


class TerminalView(QPlainTextEdit):
    """Render a remote PTY screen and optionally send keystrokes directly."""

    input_requested = Signal(str)
    focus_command_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setFont(QFont('Consolas', 11))
        self.screen = pyte.Screen(80, 24)
        self.stream = pyte.Stream(self.screen)
        self.interactive = False
        self._previous_display = None
        self._cursor_visible = True

    def set_interactive(self, enabled):
        self.interactive = bool(enabled)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus if enabled else Qt.FocusPolicy.ClickFocus)

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        if not self.interactive:
            self.focus_command_requested.emit()

    def dimensions(self):
        fm = self.fontMetrics()
        # A monospaced terminal must use its own fixed character grid.
        char_width = max(1, fm.horizontalAdvance('M'))
        char_height = max(1, fm.lineSpacing())
        return (max(20, (self.viewport().width() - 6) // char_width),
                max(8, (self.viewport().height() - 6) // char_height))

    def resize_screen(self, columns, rows):
        if (columns, rows) == (self.screen.columns, self.screen.lines):
            return
        self.screen.resize(rows, columns)
        self._previous_display = None
        self.render()

    def feed(self, text):
        self.stream.feed(text)
        self.render()

    def render(self):
        # pyte handles cursor addressing, clearing, CR/LF, and ANSI screen control.
        # Display is a fixed-width grid, not a cumulative text log.
        display = '\n'.join(self.screen.display)
        if display == self._previous_display:
            return
        self._previous_display = display
        self.setPlainText(display)
        # Keep the display anchored to the top while full-screen apps redraw.
        self.verticalScrollBar().setValue(0)
        self.update_cursor_indicator()

    def update_cursor_indicator(self):
        if not self._cursor_visible:
            self.setExtraSelections([])
            return
        row = min(self.screen.cursor.y, self.document().blockCount() - 1)
        block = self.document().findBlockByNumber(max(0, row))
        if not block.isValid():
            return
        cursor = QTextCursor(block)
        cursor.movePosition(QTextCursor.MoveOperation.Right,
                            QTextCursor.MoveMode.MoveAnchor,
                            min(self.screen.cursor.x, max(0, block.length() - 1)))
        cursor.movePosition(QTextCursor.MoveOperation.Right,
                            QTextCursor.MoveMode.KeepAnchor)
        highlight = QTextEdit.ExtraSelection()
        highlight.cursor = cursor
        highlight.format.setBackground(QColor('#d6c1f7'))
        highlight.format.setForeground(QColor('#100d1a'))
        self.setExtraSelections([highlight])

    def set_cursor_visible(self, visible):
        self._cursor_visible = bool(visible)
        self.update_cursor_indicator()

    def keyPressEvent(self, event: QKeyEvent):
        if not self.interactive:
            super().keyPressEvent(event)
            return
        key = event.key()
        modifiers = event.modifiers()
        ctrl = bool(modifiers & Qt.KeyboardModifier.ControlModifier)
        shift = bool(modifiers & Qt.KeyboardModifier.ShiftModifier)
        if ctrl and shift and key == Qt.Key.Key_C:
            self.copy()
            return
        if ctrl and key == Qt.Key.Key_C:
            self.input_requested.emit('\x03')
            return
        if ctrl and key == Qt.Key.Key_D:
            self.input_requested.emit('\x04')
            return
        if ctrl and key == Qt.Key.Key_Z:
            self.input_requested.emit('\x1a')
            return
        if ctrl and Qt.Key.Key_A <= key <= Qt.Key.Key_Z:
            self.input_requested.emit(chr(key - Qt.Key.Key_A + 1))
            return
        special = {
            Qt.Key.Key_Up: '\x1b[A', Qt.Key.Key_Down: '\x1b[B',
            Qt.Key.Key_Right: '\x1b[C', Qt.Key.Key_Left: '\x1b[D',
            Qt.Key.Key_Home: '\x1b[H', Qt.Key.Key_End: '\x1b[F',
            Qt.Key.Key_Delete: '\x1b[3~', Qt.Key.Key_Insert: '\x1b[2~',
            Qt.Key.Key_PageUp: '\x1b[5~', Qt.Key.Key_PageDown: '\x1b[6~',
            Qt.Key.Key_Return: '\r', Qt.Key.Key_Enter: '\r',
            Qt.Key.Key_Backspace: '\x7f', Qt.Key.Key_Tab: '\t',
            Qt.Key.Key_Escape: '\x1b',
        }
        for index in range(1, 13):
            special[getattr(Qt.Key, f'Key_F{index}')] = (
                ['\x1bOP', '\x1bOQ', '\x1bOR', '\x1bOS'][index - 1]
                if index <= 4 else f'\x1b[{index + 10}~')
        value = special.get(key, event.text())
        if value:
            self.input_requested.emit(value)
        event.accept()
