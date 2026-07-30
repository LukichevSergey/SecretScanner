"""Desktop interface for SecretScanner."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox

from secret_scanner.config import default_config
from secret_scanner.models import PatternRule, RiskLevel
from secret_scanner.patterns import get_all_rules
from secret_scanner.scanner import SecretScannerEngine


def default_settings_path() -> Path:
    """Location of the persisted GUI settings (overridable for tests/portable use)."""
    override = os.environ.get("SECRETSCANNER_SETTINGS")
    if override:
        return Path(override)
    return Path.home() / ".secretscanner" / "gui_settings.json"


SETTINGS_PATH = default_settings_path()


BG = "#050810"
PANEL = "#0A101C"
PANEL_ALT = "#0D1526"
FIELD = "#060B15"
BORDER = "#1B2740"
CYAN = "#00E5FF"
CYAN_BRIGHT = "#7CF5FF"
VIOLET = "#B14EFF"
TEXT = "#E4F6FF"
MUTED = "#5A7191"
SUCCESS = "#39FF9E"
WARNING = "#FF2A6D"
LOG_BG = "#03060C"

RISK_COLORS = {
    "Critical": WARNING,
    "High": "#FF8A3D",
    "Medium": "#FFD23F",
    "Low": CYAN,
}

# Monospaced family per platform; resolved once a Tk root exists.
_MONO_CANDIDATES = ("Menlo", "Consolas", "DejaVu Sans Mono", "Liberation Mono", "Courier New")
_MONO_FAMILY = "Courier"


def _resolve_mono_family() -> str:
    """Pick the first available monospaced family for the current platform."""
    global _MONO_FAMILY
    try:
        from tkinter import font as tkfont

        available = {f.lower() for f in tkfont.families()}
        for candidate in _MONO_CANDIDATES:
            if candidate.lower() in available:
                _MONO_FAMILY = candidate
                break
    except Exception:
        pass
    return _MONO_FAMILY


def F(size: int, bold: bool = False) -> tuple:
    """Build a monospaced font tuple in the resolved platform family."""
    return (_MONO_FAMILY, size, "bold") if bold else (_MONO_FAMILY, size)


class GlowButton(tk.Frame):
    """Flat clickable button built from Frame+Label.

    Plain tk.Button ignores custom bg/fg on macOS Aqua (native pill style),
    so a label-based widget is used instead to get real theme colors.
    """

    def __init__(
        self,
        parent: tk.Widget,
        text: str,
        command,
        *,
        bg: str,
        fg: str,
        hover_bg: str,
        disabled_bg: str,
        disabled_fg: str,
        font: tuple,
        border: str | None = None,
        padx: int = 20,
        pady: int = 12,
    ) -> None:
        super().__init__(parent, bg=bg, highlightthickness=1, highlightbackground=border or bg, cursor="hand2")
        self._command = command
        self._bg = bg
        self._fg = fg
        self._hover_bg = hover_bg
        self._disabled_bg = disabled_bg
        self._disabled_fg = disabled_fg
        self._border = border
        self._enabled = True
        self.label = tk.Label(self, text=text, font=font, bg=bg, fg=fg, padx=padx, pady=pady, cursor="hand2")
        self.label.pack()
        for widget in (self, self.label):
            widget.bind("<Button-1>", self._on_click)
            widget.bind("<Enter>", self._on_enter)
            widget.bind("<Leave>", self._on_leave)

    def _on_click(self, _event: object) -> None:
        if self._enabled:
            self._command()

    def _on_enter(self, _event: object) -> None:
        if self._enabled:
            super().config(bg=self._hover_bg, highlightbackground=self._border or self._hover_bg)
            self.label.config(bg=self._hover_bg)

    def _on_leave(self, _event: object) -> None:
        if self._enabled:
            super().config(bg=self._bg, highlightbackground=self._border or self._bg)
            self.label.config(bg=self._bg)

    def config(self, **kwargs) -> None:  # type: ignore[override]
        if "state" in kwargs:
            state = kwargs.pop("state")
            self._enabled = state != tk.DISABLED
            if self._enabled:
                super().config(bg=self._bg, highlightbackground=self._border or self._bg, cursor="hand2")
                self.label.config(bg=self._bg, fg=self._fg, cursor="hand2")
            else:
                super().config(bg=self._disabled_bg, highlightbackground=self._disabled_bg, cursor="arrow")
                self.label.config(bg=self._disabled_bg, fg=self._disabled_fg, cursor="arrow")
        if kwargs:
            super().config(**kwargs)

    configure = config


class SecretScannerGUI(tk.Tk):
    """Native, compact desktop window for configuring and running an audit."""

    def __init__(self, settings_path: Path | None = None) -> None:
        super().__init__()
        self.settings_path = Path(settings_path) if settings_path else default_settings_path()
        _resolve_mono_family()
        self.title("SecretScanner // Security Audit Console")
        window_w = min(1180, int(self.winfo_screenwidth() * 0.9))
        window_h = min(1000, int(self.winfo_screenheight() * 0.88))
        self.geometry(f"{window_w}x{window_h}")
        self.minsize(min(1040, window_w), min(840, window_h))
        self.configure(bg=BG)

        self.project_path_var = tk.StringVar()
        self.output_dir_var = tk.StringVar()
        self.excluded_dirs_var = tk.StringVar(
            value="DerivedData, .build, .git, Pods, Carthage, node_modules, vendor, dist, build"
        )
        self.excluded_files_var = tk.StringVar(
            value=".DS_Store, package-lock.json, yarn.lock, Podfile.lock"
        )
        self.fmt_html_var = tk.BooleanVar(value=True)
        self.fmt_json_var = tk.BooleanVar(value=True)
        self.fmt_md_var = tk.BooleanVar(value=True)
        self.fmt_txt_var = tk.BooleanVar(value=True)
        self.brief_report_var = tk.BooleanVar(value=False)
        self.enable_git_var = tk.BooleanVar(value=True)
        self.enable_entropy_var = tk.BooleanVar(value=True)
        self.entropy_threshold_var = tk.DoubleVar(value=4.5)
        self.workers_var = tk.IntVar(value=8)
        self.status_var = tk.StringVar(value="ГОТОВ К АУДИТУ")
        self.last_report_path: Path | None = None
        self._cursor_on = True

        # Rule configuration (edited in the rules window, persisted with the rest)
        self.disabled_rule_ids: set[str] = set()
        self.custom_keywords: list[str] = []
        self.custom_rules: list[dict] = []
        self._rules_window: tk.Toplevel | None = None

        self._load_settings()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        if sys.platform == "darwin":
            # Cmd-Q bypasses WM_DELETE_WINDOW on macOS, so settings would be lost
            self.createcommand("tk::mac::Quit", self._on_close)
        self.after(600, self._blink_cursor)

    # ---------------------------------------------------------------- widgets

    def _panel(self, parent: tk.Widget, number: str, title: str, hint: str = "") -> tuple[tk.Frame, tk.Frame]:
        outer = tk.Frame(parent, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        inner = tk.Frame(outer, bg=PANEL)
        inner.pack(fill=tk.BOTH, expand=True, padx=18, pady=16)

        title_row = tk.Frame(inner, bg=PANEL)
        title_row.pack(fill=tk.X)
        tk.Label(title_row, text=number, font=F(12, True), bg=PANEL, fg=VIOLET).pack(side=tk.LEFT)
        tk.Label(title_row, text="  " + title, font=F(12, True), bg=PANEL, fg=TEXT).pack(side=tk.LEFT)

        tk.Frame(inner, bg=CYAN, height=2).pack(fill=tk.X, pady=(8, 0))

        if hint:
            tk.Label(inner, text=hint, font=F(9), bg=PANEL, fg=MUTED, anchor="w", justify=tk.LEFT).pack(
                fill=tk.X, pady=(6, 14)
            )
        else:
            tk.Frame(inner, bg=PANEL, height=10).pack()

        body = tk.Frame(inner, bg=PANEL)
        body.pack(fill=tk.BOTH, expand=True)
        return outer, body

    def _entry(self, parent: tk.Widget, variable: tk.StringVar) -> tk.Entry:
        return tk.Entry(
            parent,
            textvariable=variable,
            font=F(10),
            bg=FIELD,
            fg=TEXT,
            insertbackground=CYAN,
            relief=tk.FLAT,
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=CYAN,
        )

    def _primary_button(self, parent: tk.Widget, text: str, command) -> GlowButton:
        return GlowButton(
            parent,
            text,
            command,
            bg=CYAN,
            fg="#04121A",
            hover_bg=CYAN_BRIGHT,
            disabled_bg="#16202C",
            disabled_fg="#3E5064",
            font=F(10, True),
        )

    def _secondary_button(self, parent: tk.Widget, text: str, command) -> GlowButton:
        return GlowButton(
            parent,
            text,
            command,
            bg=PANEL_ALT,
            fg=CYAN,
            hover_bg="#16223B",
            disabled_bg=PANEL_ALT,
            disabled_fg=MUTED,
            font=F(10),
            border=BORDER,
            padx=14,
            pady=9,
        )

    def _check(self, parent: tk.Widget, text: str, variable: tk.BooleanVar) -> tk.Frame:
        frame = tk.Frame(parent, bg=PANEL, cursor="hand2")
        box = tk.Label(frame, font=F(10, True), bg=PANEL, width=3, anchor="w")
        label = tk.Label(frame, text=text, font=F(10), bg=PANEL, fg=TEXT, cursor="hand2")
        box.pack(side=tk.LEFT)
        label.pack(side=tk.LEFT, padx=(4, 0))

        def render() -> None:
            if variable.get():
                box.config(text="[x]", fg=SUCCESS)
            else:
                box.config(text="[ ]", fg=MUTED)

        def toggle(_event: object) -> None:
            variable.set(not variable.get())
            render()

        for widget in (frame, box, label):
            widget.bind("<Button-1>", toggle)
        render()
        return frame

    def _labeled_path(self, parent: tk.Widget, label: str, variable: tk.StringVar, button_text: str, command) -> None:
        tk.Label(parent, text=label, font=F(9), bg=PANEL, fg=MUTED, anchor="w").pack(fill=tk.X, pady=(0, 6))
        row = tk.Frame(parent, bg=PANEL)
        row.pack(fill=tk.X)
        entry = self._entry(row, variable)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=6, padx=(0, 10))
        self._secondary_button(row, button_text, command).pack(side=tk.RIGHT)

    def _spinbox(self, parent: tk.Widget, variable, from_: float, to: float, increment: float, width: int) -> tk.Spinbox:
        return tk.Spinbox(
            parent,
            from_=from_,
            to=to,
            increment=increment,
            textvariable=variable,
            width=width,
            justify="center",
            font=F(10),
            bg=FIELD,
            fg=TEXT,
            buttonbackground=PANEL_ALT,
            insertbackground=CYAN,
            relief=tk.FLAT,
            highlightthickness=1,
            highlightbackground=BORDER,
        )

    # ------------------------------------------------------------------ build

    def _build_ui(self) -> None:
        root = tk.Frame(self, bg=BG, padx=28, pady=24)
        root.pack(fill=tk.BOTH, expand=True)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=0)  # workspace keeps its natural size, never gets compressed
        root.rowconfigure(2, weight=1)  # log panel absorbs any extra/short space

        # header ------------------------------------------------------------
        header = tk.Frame(root, bg=BG)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 18))
        header.columnconfigure(0, weight=1)

        title_row = tk.Frame(header, bg=BG)
        title_row.grid(row=0, column=0, sticky="w")
        tk.Label(title_row, text="SECRET", font=F(24, True), bg=BG, fg=TEXT).pack(side=tk.LEFT)
        tk.Label(title_row, text="://", font=F(24, True), bg=BG, fg=MUTED).pack(side=tk.LEFT)
        tk.Label(title_row, text="SCANNER", font=F(24, True), bg=BG, fg=CYAN).pack(side=tk.LEFT)

        subtitle_row = tk.Frame(header, bg=BG)
        subtitle_row.grid(row=1, column=0, sticky="w", pady=(4, 0))
        tk.Label(
            subtitle_row,
            text="Проверка кода на ключи, токены и конфиденциальные данные",
            font=F(11),
            bg=BG,
            fg=MUTED,
        ).pack(side=tk.LEFT)
        self.cursor_label = tk.Label(subtitle_row, text=" _", font=F(11), bg=BG, fg=CYAN)
        self.cursor_label.pack(side=tk.LEFT)

        self.status_badge = tk.Frame(header, bg=PANEL_ALT, highlightthickness=1, highlightbackground=CYAN)
        self.status_badge.grid(row=0, column=1, rowspan=2, sticky="e")
        badge_inner = tk.Frame(self.status_badge, bg=PANEL_ALT, padx=14, pady=9)
        badge_inner.pack()
        self.status_dot = tk.Label(badge_inner, text="●", font=F(10, True), bg=PANEL_ALT, fg=CYAN)
        self.status_dot.pack(side=tk.LEFT, padx=(0, 8))
        tk.Label(badge_inner, textvariable=self.status_var, font=F(10, True), bg=PANEL_ALT, fg=TEXT).pack(
            side=tk.LEFT
        )

        tk.Frame(header, bg=BORDER, height=1).grid(row=2, column=0, columnspan=2, sticky="ew", pady=(16, 0))

        # workspace -----------------------------------------------------------
        workspace = tk.Frame(root, bg=BG)
        workspace.grid(row=1, column=0, sticky="nsew")
        workspace.columnconfigure(0, weight=6, uniform="workspace")
        workspace.columnconfigure(1, weight=5, uniform="workspace")
        workspace.rowconfigure(0, weight=1)

        left = tk.Frame(workspace, bg=BG)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.columnconfigure(0, weight=1)

        project_panel, project_body = self._panel(
            left, "01", "ЦЕЛЕВОЙ ПРОЕКТ", "Выберите папку, которую нужно проверить."
        )
        project_panel.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        self._labeled_path(project_body, "ПАПКА ПРОЕКТА", self.project_path_var, "Выбрать…", self._browse_project_folder)
        tk.Frame(project_body, bg=PANEL, height=14).pack()
        self._labeled_path(
            project_body,
            "ПАПКА ДЛЯ ОТЧЁТОВ · необязательно",
            self.output_dir_var,
            "Выбрать…",
            self._browse_output_folder,
        )

        scope_panel, scope_body = self._panel(
            left, "02", "ОБЛАСТЬ ПРОВЕРКИ", "Исключения применяются к именам папок и файлов."
        )
        scope_panel.grid(row=1, column=0, sticky="ew")
        tk.Label(scope_body, text="НЕ СКАНИРОВАТЬ ПАПКИ", font=F(9), bg=PANEL, fg=MUTED, anchor="w").pack(
            fill=tk.X, pady=(0, 6)
        )
        self._entry(scope_body, self.excluded_dirs_var).pack(fill=tk.X, ipady=6)
        tk.Label(scope_body, text="НЕ СКАНИРОВАТЬ ФАЙЛЫ", font=F(9), bg=PANEL, fg=MUTED, anchor="w").pack(
            fill=tk.X, pady=(14, 6)
        )
        self._entry(scope_body, self.excluded_files_var).pack(fill=tk.X, ipady=6)

        right = tk.Frame(workspace, bg=BG)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right.columnconfigure(0, weight=1)

        output_panel, output_body = self._panel(
            right, "03", "ОТЧЁТ", "Выберите файлы, которые будут созданы после аудита."
        )
        output_panel.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        formats = tk.Frame(output_body, bg=PANEL)
        formats.pack(fill=tk.X)
        formats.columnconfigure(0, weight=1)
        formats.columnconfigure(1, weight=1)
        for index, (label, variable) in enumerate(
            (
                ("HTML · интерактивный", self.fmt_html_var),
                ("JSON · интеграции", self.fmt_json_var),
                ("Markdown", self.fmt_md_var),
                ("Text", self.fmt_txt_var),
            )
        ):
            self._check(formats, label, variable).grid(
                row=index // 2, column=index % 2, sticky="w", padx=(0, 16), pady=4
            )
        tk.Frame(output_body, bg=BORDER, height=1).pack(fill=tk.X, pady=(12, 10))
        self._check(
            output_body, "Краткий отчёт · без контекста строк", self.brief_report_var
        ).pack(anchor="w")

        engine_panel, engine_body = self._panel(
            right, "04", "ДВИЖОК СКАНИРОВАНИЯ", "Настройки по умолчанию подходят для большинства проектов."
        )
        engine_panel.grid(row=1, column=0, sticky="ew")
        self._check(engine_body, "Сканировать историю Git и stashes", self.enable_git_var).pack(
            anchor="w", pady=(0, 8)
        )
        self._check(engine_body, "Искать ключи по энтропии Шеннона", self.enable_entropy_var).pack(anchor="w")
        controls = tk.Frame(engine_body, bg=PANEL)
        controls.pack(anchor="w", pady=(14, 0))
        tk.Label(controls, text="Порог энтропии", font=F(9), bg=PANEL, fg=MUTED).grid(
            row=0, column=0, sticky="w", padx=(0, 8)
        )
        self._spinbox(controls, self.entropy_threshold_var, 3.0, 6.5, 0.1, 5).grid(row=0, column=1)
        tk.Label(controls, text="Потоки", font=F(9), bg=PANEL, fg=MUTED).grid(
            row=0, column=2, sticky="w", padx=(18, 8)
        )
        self._spinbox(controls, self.workers_var, 1, 64, 1, 4).grid(row=0, column=3)

        tk.Frame(engine_body, bg=BORDER, height=1).pack(fill=tk.X, pady=(14, 12))
        rules_row = tk.Frame(engine_body, bg=PANEL)
        rules_row.pack(fill=tk.X)
        self._secondary_button(rules_row, "⚙  ПРАВИЛА ПОИСКА", self._open_rules_window).pack(side=tk.LEFT)
        self.rules_summary_var = tk.StringVar()
        tk.Label(
            rules_row, textvariable=self.rules_summary_var, font=F(9), bg=PANEL, fg=MUTED
        ).pack(side=tk.LEFT, padx=(12, 0))
        self._refresh_rules_summary()

        # log -----------------------------------------------------------------
        log_panel, log_body = self._panel(root, "05", "АКТИВНОСТЬ", "Журнал сканирования появится здесь в реальном времени.")
        log_panel.grid(row=2, column=0, sticky="nsew", pady=(14, 12))
        log_body.pack_configure(fill=tk.BOTH, expand=True)
        tk.Label(
            log_body, text="$ tail -f audit.log", font=F(10), bg=PANEL, fg=MUTED, anchor="w"
        ).pack(fill=tk.X, pady=(0, 6))
        log_container = tk.Frame(log_body, bg=LOG_BG, highlightbackground=BORDER, highlightthickness=1)
        log_container.pack(fill=tk.BOTH, expand=True)
        self.log_text = tk.Text(
            log_container,
            wrap=tk.WORD,
            height=7,
            font=F(10),
            bg=LOG_BG,
            fg=SUCCESS,
            insertbackground=CYAN,
            bd=0,
            padx=12,
            pady=10,
            highlightthickness=0,
        )
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = tk.Scrollbar(
            log_container,
            command=self.log_text.yview,
            troughcolor=LOG_BG,
            bg=BORDER,
            activebackground=CYAN,
            highlightthickness=0,
            bd=0,
        )
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)
        self.log_text.tag_config("timestamp", foreground=MUTED)
        self.log_text.tag_config("message", foreground=SUCCESS)
        self.log_text.tag_config("success", foreground=SUCCESS)
        self.log_text.tag_config("error", foreground=WARNING)

        # footer ----------------------------------------------------------------
        footer = tk.Frame(root, bg=BG)
        footer.grid(row=3, column=0, sticky="ew")
        self.start_btn = self._primary_button(footer, "НАЧАТЬ СКАНИРОВАНИЕ", self._start_audit_thread)
        self.start_btn.pack(side=tk.LEFT)
        self.open_report_btn = self._secondary_button(footer, "Открыть HTML-отчёт", self._open_html_report)
        self.open_report_btn.config(state=tk.DISABLED)
        self.open_report_btn.pack(side=tk.LEFT, padx=(10, 0))
        tk.Label(footer, text="> все проверки выполняются локально", bg=BG, fg=MUTED, font=F(9)).pack(
            side=tk.RIGHT, pady=10
        )

        self.log("Система готова. Выберите проект и запустите проверку.")

    # ------------------------------------------------------------------ logic

    def _blink_cursor(self) -> None:
        self._cursor_on = not self._cursor_on
        self.cursor_label.config(fg=CYAN if self._cursor_on else BG)
        self.after(600, self._blink_cursor)

    def _set_status(self, text: str, color: str) -> None:
        self.status_var.set(text)
        self.status_dot.config(fg=color)
        self.status_badge.config(highlightbackground=color)

    def log(self, message: str) -> None:
        if message.startswith("\n"):
            self.log_text.insert(tk.END, message + "\n", "message")
        else:
            tag = "success" if message.startswith("✓") else "error" if "Ошибка" in message else "message"
            self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] ", "timestamp")
            self.log_text.insert(tk.END, message + "\n", tag)
        self.log_text.see(tk.END)

    def _browse_project_folder(self) -> None:
        folder = filedialog.askdirectory(title="Выберите папку проекта для аудита")
        if folder:
            self.project_path_var.set(folder)
            self.log(f"Выбрана папка проекта: {folder}")

    def _browse_output_folder(self) -> None:
        folder = filedialog.askdirectory(title="Выберите папку для сохранения отчётов")
        if folder:
            self.output_dir_var.set(folder)
            self.log(f"Выбрана папка для отчётов: {folder}")

    def _start_audit_thread(self) -> None:
        path_str = self.project_path_var.get().strip()
        if not path_str or not Path(path_str).exists():
            messagebox.showerror("Нужна папка проекта", "Выберите существующую папку проекта перед запуском аудита.")
            return
        self._save_settings()
        self.start_btn.config(state=tk.DISABLED)
        self.open_report_btn.config(state=tk.DISABLED)
        self._set_status("СКАНИРОВАНИЕ…", CYAN)
        self.log("\n" + "─" * 58)
        self.log(f"Запуск аудита: {path_str}")
        threading.Thread(target=self._run_scan_worker, args=(path_str,), daemon=True).start()

    def _run_scan_worker(self, path_str: str) -> None:
        try:
            target_path = Path(path_str).resolve()
            config = default_config(target_path)
            config.excluded_dirs.update({item.strip() for item in self.excluded_dirs_var.get().split(",") if item.strip()})
            config.excluded_files.update({item.strip() for item in self.excluded_files_var.get().split(",") if item.strip()})
            config.generate_html = self.fmt_html_var.get()
            config.generate_json = self.fmt_json_var.get()
            config.generate_markdown = self.fmt_md_var.get()
            config.generate_text = self.fmt_txt_var.get()
            config.enable_git = self.enable_git_var.get()
            config.enable_entropy = self.enable_entropy_var.get()
            config.entropy_threshold = self.entropy_threshold_var.get()
            config.max_workers = self.workers_var.get()
            config.context_lines = 0 if self.brief_report_var.get() else 20
            config.disabled_rule_ids = set(self.disabled_rule_ids)
            config.custom_keywords = set(self.custom_keywords)
            config.custom_rules = self._build_custom_rule_objects()
            out_dir = self.output_dir_var.get().strip()
            out_path = Path(out_dir).resolve() if out_dir else target_path
            report = SecretScannerEngine(config).run(output_dir=out_path)
            self.last_report_path = Path(report.output_dir) / "report.html"
            self.after(0, self._scan_completed_success, report)
        except Exception as err:
            self.after(0, self._scan_completed_error, str(err))

    def _scan_completed_success(self, report) -> None:
        stats = report.stats
        self.log("\n" + "─" * 58)
        self.log("✓ СКАНИРОВАНИЕ ЗАВЕРШЕНО")
        self.log(f"Проверено файлов: {stats.files_scanned}  ·  строк: {stats.lines_scanned:,}  ·  время: {stats.elapsed_time_seconds:.2f} сек")
        self.log(f"Найдено секретов: {stats.total_findings}  ·  Critical: {stats.critical_count}  ·  High: {stats.high_count}  ·  Medium: {stats.medium_count}  ·  Low: {stats.low_count}")
        self.start_btn.config(state=tk.NORMAL)
        if self.fmt_html_var.get():
            self.open_report_btn.config(state=tk.NORMAL)
        if stats.total_findings:
            self._set_status(f"ГОТОВО · РИСКОВ: {stats.total_findings}", WARNING)
            messagebox.showwarning("Сканирование завершено", f"Аудит завершён. Найдено рисков: {stats.total_findings}.\nОткройте HTML-отчёт для подробностей.")
        else:
            self._set_status("ГОТОВО · ЧИСТО", SUCCESS)
            messagebox.showinfo("Сканирование завершено", "Аудит завершён. Утечек информации не найдено.")

    def _scan_completed_error(self, error_msg: str) -> None:
        self.log(f"\nОшибка сканирования: {error_msg}")
        self.start_btn.config(state=tk.NORMAL)
        self._set_status("ОШИБКА СКАНИРОВАНИЯ", WARNING)
        messagebox.showerror("Ошибка", f"Произошла ошибка при аудите:\n{error_msg}")

    def _open_html_report(self) -> None:
        if not (self.last_report_path and self.last_report_path.exists()):
            messagebox.showerror("Отчёт не найден", "Файл report.html не найден. Проверьте, что формат HTML был включён.")
            return
        try:
            if sys.platform == "darwin":
                subprocess.run(["open", str(self.last_report_path)], check=True)
            else:
                webbrowser.open(self.last_report_path.resolve().as_uri())
        except Exception as err:
            messagebox.showerror("Не удалось открыть отчёт", f"Не удалось открыть report.html:\n{err}")

    # ------------------------------------------------------------------ rules

    def _build_custom_rule_objects(self) -> list[PatternRule]:
        """Turn the stored custom-rule dicts into PatternRule objects, skipping broken regexes."""
        built: list[PatternRule] = []
        for entry in self.custom_rules:
            pattern = entry.get("pattern", "")
            try:
                re.compile(pattern)
            except re.error:
                continue
            try:
                risk = RiskLevel(entry.get("risk", "High"))
            except ValueError:
                risk = RiskLevel.HIGH
            built.append(
                PatternRule(
                    id=entry.get("id", "CUSTOM"),
                    name=entry.get("name") or "Custom Rule",
                    pattern=pattern,
                    risk_level=risk,
                    description="User-defined detection rule.",
                    recommendation="Review this match and move the value out of the repository if it is a secret.",
                    category="Custom",
                )
            )
        return built

    def _refresh_rules_summary(self) -> None:
        total = len(get_all_rules())
        active = total - len([r for r in get_all_rules() if r.id in self.disabled_rule_ids])
        extra = len(self.custom_rules) + (1 if self.custom_keywords else 0)
        text = f"активно {active} из {total}"
        if extra:
            text += f"  +{extra} свои"
        self.rules_summary_var.set(text)

    def _open_rules_window(self) -> None:
        if self._rules_window is not None and self._rules_window.winfo_exists():
            self._rules_window.lift()
            self._rules_window.focus_force()
            return

        win = tk.Toplevel(self)
        self._rules_window = win
        win.title("Правила поиска")
        win.configure(bg=BG)
        w = min(900, int(self.winfo_screenwidth() * 0.7))
        h = min(820, int(self.winfo_screenheight() * 0.8))
        win.geometry(f"{w}x{h}")
        win.minsize(760, 560)
        win.transient(self)

        def on_close() -> None:
            self._collect_rules_from_window()
            self._refresh_rules_summary()
            self._save_settings()
            self._rules_window = None
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", on_close)
        self._build_rules_window(win, on_close)

    def _build_rules_window(self, win: tk.Toplevel, on_close) -> None:
        header = tk.Frame(win, bg=BG, padx=22, pady=18)
        header.pack(fill=tk.X)
        tk.Label(header, text="ПРАВИЛА ПОИСКА", font=F(16, True), bg=BG, fg=CYAN).pack(anchor="w")
        tk.Label(
            header,
            text="Отключите лишние проверки, добавьте свои ключевые слова или регулярные выражения.",
            font=F(9),
            bg=BG,
            fg=MUTED,
        ).pack(anchor="w", pady=(4, 0))

        body = tk.Frame(win, bg=BG, padx=22)
        body.pack(fill=tk.BOTH, expand=True)

        # --- custom keywords ------------------------------------------------
        kw_box = tk.Frame(body, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        kw_box.pack(fill=tk.X, pady=(0, 12))
        kw_inner = tk.Frame(kw_box, bg=PANEL, padx=16, pady=14)
        kw_inner.pack(fill=tk.X)
        tk.Label(kw_inner, text="СВОИ КЛЮЧЕВЫЕ СЛОВА", font=F(11, True), bg=PANEL, fg=TEXT).pack(anchor="w")
        tk.Label(
            kw_inner,
            text="Любая переменная, в имени которой есть это слово, будет проверена. Например: mapkit, yandex, vk",
            font=F(9),
            bg=PANEL,
            fg=MUTED,
            wraplength=780,
            justify=tk.LEFT,
        ).pack(anchor="w", pady=(4, 8))
        self.keywords_var = tk.StringVar(value=", ".join(self.custom_keywords))
        self._entry(kw_inner, self.keywords_var).pack(fill=tk.X, ipady=6)

        # --- custom regex rules ---------------------------------------------
        cr_box = tk.Frame(body, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        cr_box.pack(fill=tk.X, pady=(0, 12))
        cr_inner = tk.Frame(cr_box, bg=PANEL, padx=16, pady=14)
        cr_inner.pack(fill=tk.X)
        title_row = tk.Frame(cr_inner, bg=PANEL)
        title_row.pack(fill=tk.X)
        tk.Label(title_row, text="СВОИ РЕГУЛЯРНЫЕ ВЫРАЖЕНИЯ", font=F(11, True), bg=PANEL, fg=TEXT).pack(side=tk.LEFT)
        self._secondary_button(title_row, "+ Добавить", self._add_custom_rule_dialog).pack(side=tk.RIGHT)
        self.custom_rules_list = tk.Frame(cr_inner, bg=PANEL)
        self.custom_rules_list.pack(fill=tk.X, pady=(10, 0))
        self._render_custom_rules()

        # --- built-in rules, grouped by category ----------------------------
        list_box = tk.Frame(body, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        list_box.pack(fill=tk.BOTH, expand=True)
        list_inner = tk.Frame(list_box, bg=PANEL, padx=16, pady=14)
        list_inner.pack(fill=tk.BOTH, expand=True)

        head_row = tk.Frame(list_inner, bg=PANEL)
        head_row.pack(fill=tk.X, pady=(0, 8))
        tk.Label(head_row, text="ВСТРОЕННЫЕ ПРОВЕРКИ", font=F(11, True), bg=PANEL, fg=TEXT).pack(side=tk.LEFT)
        self._secondary_button(head_row, "Снять все", lambda: self._toggle_all_rules(False)).pack(side=tk.RIGHT)
        self._secondary_button(head_row, "Включить все", lambda: self._toggle_all_rules(True)).pack(
            side=tk.RIGHT, padx=(0, 8)
        )

        canvas = tk.Canvas(list_inner, bg=PANEL, highlightthickness=0, bd=0)
        scroll = tk.Scrollbar(list_inner, command=canvas.yview, troughcolor=PANEL, bg=BORDER,
                              activebackground=CYAN, highlightthickness=0, bd=0)
        holder = tk.Frame(canvas, bg=PANEL)
        holder.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        window_id = canvas.create_window((0, 0), window=holder, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window_id, width=e.width))
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._bind_mousewheel(canvas)

        self.rule_vars: dict[str, tk.BooleanVar] = {}
        by_category: dict[str, list] = {}
        for rule in get_all_rules():
            by_category.setdefault(rule.category, []).append(rule)

        for category, rules in by_category.items():
            cat_row = tk.Frame(holder, bg=PANEL)
            cat_row.pack(fill=tk.X, pady=(10, 4))
            tk.Label(cat_row, text=f"── {category.upper()}", font=F(9, True), bg=PANEL, fg=VIOLET).pack(anchor="w")
            for rule in rules:
                var = tk.BooleanVar(value=rule.id not in self.disabled_rule_ids)
                self.rule_vars[rule.id] = var
                row = tk.Frame(holder, bg=PANEL)
                row.pack(fill=tk.X, pady=1)
                self._check(row, "", var).pack(side=tk.LEFT)
                tk.Label(
                    row, text=rule.name, font=F(10), bg=PANEL, fg=TEXT, anchor="w"
                ).pack(side=tk.LEFT)
                tk.Label(
                    row,
                    text=rule.risk_level.value.upper(),
                    font=F(8, True),
                    bg=PANEL,
                    fg=RISK_COLORS.get(rule.risk_level.value, MUTED),
                ).pack(side=tk.RIGHT, padx=(8, 0))

        footer = tk.Frame(win, bg=BG, padx=22, pady=16)
        footer.pack(fill=tk.X)
        self._primary_button(footer, "СОХРАНИТЬ И ЗАКРЫТЬ", on_close).pack(side=tk.LEFT)
        tk.Label(
            footer, text="> настройки сохраняются между запусками", bg=BG, fg=MUTED, font=F(9)
        ).pack(side=tk.RIGHT)

    @staticmethod
    def _bind_mousewheel(canvas: tk.Canvas) -> None:
        """
        Route wheel events to the canvas only while the pointer is over it.

        Wheel deltas differ per platform (±120 on Windows, small values on macOS)
        and X11 reports buttons 4/5 instead. Binding is scoped with Enter/Leave so
        the global binding cannot outlive this canvas.
        """

        def on_wheel(event: tk.Event) -> None:
            if getattr(event, "num", None) == 4:
                canvas.yview_scroll(-3, "units")
            elif getattr(event, "num", None) == 5:
                canvas.yview_scroll(3, "units")
            elif sys.platform == "win32":
                canvas.yview_scroll(int(-event.delta / 120) * 3, "units")
            else:
                canvas.yview_scroll(-event.delta, "units")

        def grab(_event: object) -> None:
            canvas.bind_all("<MouseWheel>", on_wheel)
            canvas.bind_all("<Button-4>", on_wheel)
            canvas.bind_all("<Button-5>", on_wheel)

        def release(_event: object) -> None:
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")

        canvas.bind("<Enter>", grab)
        canvas.bind("<Leave>", release)
        canvas.bind("<Destroy>", release)

    def _toggle_all_rules(self, enabled: bool) -> None:
        for var in self.rule_vars.values():
            var.set(enabled)
        # The checkbox widgets render from their variable, so rebuild the window body
        self._collect_rules_from_window()
        win = self._rules_window
        if win is not None and win.winfo_exists():
            for child in win.winfo_children():
                child.destroy()
            self._build_rules_window(win, lambda: self._close_rules_window(win))

    def _close_rules_window(self, win: tk.Toplevel) -> None:
        self._collect_rules_from_window()
        self._refresh_rules_summary()
        self._save_settings()
        self._rules_window = None
        win.destroy()

    def _collect_rules_from_window(self) -> None:
        """Pull the current widget state back into the persisted rule configuration."""
        if hasattr(self, "rule_vars"):
            self.disabled_rule_ids = {rid for rid, var in self.rule_vars.items() if not var.get()}
        if hasattr(self, "keywords_var"):
            self.custom_keywords = [
                k.strip() for k in self.keywords_var.get().split(",") if k.strip()
            ]

    def _render_custom_rules(self) -> None:
        for child in self.custom_rules_list.winfo_children():
            child.destroy()
        if not self.custom_rules:
            tk.Label(
                self.custom_rules_list,
                text="пока нет — нажмите «Добавить»",
                font=F(9),
                bg=PANEL,
                fg=MUTED,
            ).pack(anchor="w")
            return
        for entry in list(self.custom_rules):
            row = tk.Frame(self.custom_rules_list, bg=PANEL)
            row.pack(fill=tk.X, pady=2)
            tk.Label(
                row, text=entry.get("name", "?"), font=F(10, True), bg=PANEL, fg=TEXT
            ).pack(side=tk.LEFT)
            tk.Label(
                row, text="  " + entry.get("pattern", "")[:60], font=F(9), bg=PANEL, fg=MUTED
            ).pack(side=tk.LEFT)
            delete = tk.Label(row, text="удалить", font=F(9), bg=PANEL, fg=WARNING, cursor="hand2")
            delete.pack(side=tk.RIGHT)
            delete.bind("<Button-1>", lambda _e, item=entry: self._delete_custom_rule(item))

    def _delete_custom_rule(self, entry: dict) -> None:
        if entry in self.custom_rules:
            self.custom_rules.remove(entry)
        self._render_custom_rules()
        self._refresh_rules_summary()

    def _add_custom_rule_dialog(self) -> None:
        parent = self._rules_window or self
        dialog = tk.Toplevel(parent)
        dialog.title("Своё правило")
        dialog.configure(bg=BG)
        dialog.geometry("560x340")
        dialog.transient(parent)
        dialog.grab_set()

        body = tk.Frame(dialog, bg=BG, padx=22, pady=20)
        body.pack(fill=tk.BOTH, expand=True)
        tk.Label(body, text="НОВОЕ ПРАВИЛО", font=F(13, True), bg=BG, fg=CYAN).pack(anchor="w", pady=(0, 12))

        name_var = tk.StringVar()
        pattern_var = tk.StringVar()
        risk_var = tk.StringVar(value="High")

        tk.Label(body, text="НАЗВАНИЕ", font=F(9), bg=BG, fg=MUTED).pack(anchor="w")
        tk.Entry(
            body, textvariable=name_var, font=F(10), bg=FIELD, fg=TEXT, insertbackground=CYAN,
            relief=tk.FLAT, highlightthickness=1, highlightbackground=BORDER, highlightcolor=CYAN,
        ).pack(fill=tk.X, ipady=6, pady=(4, 12))

        tk.Label(body, text="РЕГУЛЯРНОЕ ВЫРАЖЕНИЕ (Python re)", font=F(9), bg=BG, fg=MUTED).pack(anchor="w")
        tk.Entry(
            body, textvariable=pattern_var, font=F(10), bg=FIELD, fg=TEXT, insertbackground=CYAN,
            relief=tk.FLAT, highlightthickness=1, highlightbackground=BORDER, highlightcolor=CYAN,
        ).pack(fill=tk.X, ipady=6, pady=(4, 12))

        risk_row = tk.Frame(body, bg=BG)
        risk_row.pack(fill=tk.X, pady=(0, 8))
        tk.Label(risk_row, text="УРОВЕНЬ РИСКА", font=F(9), bg=BG, fg=MUTED).pack(side=tk.LEFT, padx=(0, 10))
        for level in ("Critical", "High", "Medium", "Low"):
            lbl = tk.Label(
                risk_row, text=level, font=F(9, True), bg=PANEL_ALT,
                fg=RISK_COLORS.get(level, TEXT), padx=10, pady=5, cursor="hand2",
            )
            lbl.pack(side=tk.LEFT, padx=(0, 6))

            def select(_e: object, chosen: str = level, widget: tk.Label = lbl) -> None:
                risk_var.set(chosen)
                for sibling in risk_row.winfo_children():
                    if isinstance(sibling, tk.Label) and sibling is not risk_row.winfo_children()[0]:
                        sibling.config(bg=PANEL_ALT)
                widget.config(bg=BORDER)

            lbl.bind("<Button-1>", select)
            if level == "High":
                lbl.config(bg=BORDER)

        error_var = tk.StringVar()
        tk.Label(body, textvariable=error_var, font=F(9), bg=BG, fg=WARNING, wraplength=500,
                 justify=tk.LEFT).pack(anchor="w", pady=(4, 0))

        def save() -> None:
            name = name_var.get().strip()
            pattern = pattern_var.get().strip()
            if not name or not pattern:
                error_var.set("Заполните название и регулярное выражение.")
                return
            try:
                re.compile(pattern)
            except re.error as err:
                error_var.set(f"Некорректное регулярное выражение: {err}")
                return
            existing = {e.get("id") for e in self.custom_rules}
            index = 1
            while f"CUSTOM-{index}" in existing:
                index += 1
            self.custom_rules.append(
                {"id": f"CUSTOM-{index}", "name": name, "pattern": pattern, "risk": risk_var.get()}
            )
            self._render_custom_rules()
            self._refresh_rules_summary()
            dialog.destroy()

        buttons = tk.Frame(body, bg=BG)
        buttons.pack(fill=tk.X, pady=(14, 0))
        self._primary_button(buttons, "ДОБАВИТЬ", save).pack(side=tk.LEFT)
        self._secondary_button(buttons, "Отмена", dialog.destroy).pack(side=tk.LEFT, padx=(10, 0))

    # --------------------------------------------------------------- settings

    def _load_settings(self) -> None:
        try:
            data = json.loads(self.settings_path.read_text(encoding="utf-8"))
        except Exception:
            return
        self.project_path_var.set(data.get("project_path", self.project_path_var.get()))
        self.output_dir_var.set(data.get("output_dir", self.output_dir_var.get()))
        self.excluded_dirs_var.set(data.get("excluded_dirs", self.excluded_dirs_var.get()))
        self.excluded_files_var.set(data.get("excluded_files", self.excluded_files_var.get()))
        self.fmt_html_var.set(data.get("fmt_html", self.fmt_html_var.get()))
        self.fmt_json_var.set(data.get("fmt_json", self.fmt_json_var.get()))
        self.fmt_md_var.set(data.get("fmt_md", self.fmt_md_var.get()))
        self.fmt_txt_var.set(data.get("fmt_txt", self.fmt_txt_var.get()))
        self.brief_report_var.set(data.get("brief_report", self.brief_report_var.get()))
        self.enable_git_var.set(data.get("enable_git", self.enable_git_var.get()))
        self.enable_entropy_var.set(data.get("enable_entropy", self.enable_entropy_var.get()))
        self.entropy_threshold_var.set(data.get("entropy_threshold", self.entropy_threshold_var.get()))
        self.workers_var.set(data.get("workers", self.workers_var.get()))
        self.disabled_rule_ids = set(data.get("disabled_rule_ids", []))
        self.custom_keywords = list(data.get("custom_keywords", []))
        self.custom_rules = [r for r in data.get("custom_rules", []) if isinstance(r, dict)]

    def _save_settings(self) -> None:
        data = {
            "project_path": self.project_path_var.get(),
            "output_dir": self.output_dir_var.get(),
            "excluded_dirs": self.excluded_dirs_var.get(),
            "excluded_files": self.excluded_files_var.get(),
            "fmt_html": self.fmt_html_var.get(),
            "fmt_json": self.fmt_json_var.get(),
            "fmt_md": self.fmt_md_var.get(),
            "fmt_txt": self.fmt_txt_var.get(),
            "brief_report": self.brief_report_var.get(),
            "enable_git": self.enable_git_var.get(),
            "enable_entropy": self.enable_entropy_var.get(),
            "entropy_threshold": self.entropy_threshold_var.get(),
            "workers": self.workers_var.get(),
            "disabled_rule_ids": sorted(self.disabled_rule_ids),
            "custom_keywords": self.custom_keywords,
            "custom_rules": self.custom_rules,
        }
        try:
            self.settings_path.parent.mkdir(parents=True, exist_ok=True)
            self.settings_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    def _on_close(self) -> None:
        self._save_settings()
        self.destroy()


def launch_gui() -> None:
    app = SecretScannerGUI()
    app.mainloop()
