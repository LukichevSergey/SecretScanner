"""Desktop interface for SecretScanner."""

from __future__ import annotations

import threading
import time
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox

from secret_scanner.config import default_config
from secret_scanner.scanner import SecretScannerEngine


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

FONT_TITLE = ("Menlo", 24, "bold")
FONT_SUBTITLE = ("Menlo", 11)
FONT_SECTION = ("Menlo", 12, "bold")
FONT_NUMBER = ("Menlo", 12, "bold")
FONT_HINT = ("Menlo", 9)
FONT_MONO = ("Menlo", 10)
FONT_MONO_BOLD = ("Menlo", 10, "bold")
FONT_LOG = ("Menlo", 10)


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

    def __init__(self) -> None:
        super().__init__()
        self.title("SecretScanner // Security Audit Console")
        self.geometry("1080x780")
        self.minsize(920, 680)
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
        self.enable_git_var = tk.BooleanVar(value=True)
        self.enable_entropy_var = tk.BooleanVar(value=True)
        self.entropy_threshold_var = tk.DoubleVar(value=4.5)
        self.workers_var = tk.IntVar(value=8)
        self.status_var = tk.StringVar(value="ГОТОВ К АУДИТУ")
        self.last_report_path: Path | None = None
        self._cursor_on = True

        self._build_ui()
        self.after(600, self._blink_cursor)

    # ---------------------------------------------------------------- widgets

    def _panel(self, parent: tk.Widget, number: str, title: str, hint: str = "") -> tuple[tk.Frame, tk.Frame]:
        outer = tk.Frame(parent, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        inner = tk.Frame(outer, bg=PANEL)
        inner.pack(fill=tk.BOTH, expand=True, padx=18, pady=16)

        title_row = tk.Frame(inner, bg=PANEL)
        title_row.pack(fill=tk.X)
        tk.Label(title_row, text=number, font=FONT_NUMBER, bg=PANEL, fg=VIOLET).pack(side=tk.LEFT)
        tk.Label(title_row, text="  " + title, font=FONT_SECTION, bg=PANEL, fg=TEXT).pack(side=tk.LEFT)

        tk.Frame(inner, bg=CYAN, height=2).pack(fill=tk.X, pady=(8, 0))

        if hint:
            tk.Label(inner, text=hint, font=FONT_HINT, bg=PANEL, fg=MUTED, anchor="w", justify=tk.LEFT).pack(
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
            font=FONT_MONO,
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
            font=FONT_MONO_BOLD,
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
            font=FONT_MONO,
            border=BORDER,
            padx=14,
            pady=9,
        )

    def _check(self, parent: tk.Widget, text: str, variable: tk.BooleanVar) -> tk.Frame:
        frame = tk.Frame(parent, bg=PANEL, cursor="hand2")
        box = tk.Label(frame, font=FONT_MONO_BOLD, bg=PANEL, width=3, anchor="w")
        label = tk.Label(frame, text=text, font=FONT_MONO, bg=PANEL, fg=TEXT, cursor="hand2")
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
        tk.Label(parent, text=label, font=FONT_HINT, bg=PANEL, fg=MUTED, anchor="w").pack(fill=tk.X, pady=(0, 6))
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
            font=FONT_MONO,
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
        root.rowconfigure(1, weight=1)
        root.rowconfigure(2, weight=1)

        # header ------------------------------------------------------------
        header = tk.Frame(root, bg=BG)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 18))
        header.columnconfigure(0, weight=1)

        title_row = tk.Frame(header, bg=BG)
        title_row.grid(row=0, column=0, sticky="w")
        tk.Label(title_row, text="SECRET", font=FONT_TITLE, bg=BG, fg=TEXT).pack(side=tk.LEFT)
        tk.Label(title_row, text="://", font=FONT_TITLE, bg=BG, fg=MUTED).pack(side=tk.LEFT)
        tk.Label(title_row, text="SCANNER", font=FONT_TITLE, bg=BG, fg=CYAN).pack(side=tk.LEFT)

        subtitle_row = tk.Frame(header, bg=BG)
        subtitle_row.grid(row=1, column=0, sticky="w", pady=(4, 0))
        tk.Label(
            subtitle_row,
            text="Проверка кода на ключи, токены и конфиденциальные данные",
            font=FONT_SUBTITLE,
            bg=BG,
            fg=MUTED,
        ).pack(side=tk.LEFT)
        self.cursor_label = tk.Label(subtitle_row, text=" _", font=FONT_SUBTITLE, bg=BG, fg=CYAN)
        self.cursor_label.pack(side=tk.LEFT)

        self.status_badge = tk.Frame(header, bg=PANEL_ALT, highlightthickness=1, highlightbackground=CYAN)
        self.status_badge.grid(row=0, column=1, rowspan=2, sticky="e")
        badge_inner = tk.Frame(self.status_badge, bg=PANEL_ALT, padx=14, pady=9)
        badge_inner.pack()
        self.status_dot = tk.Label(badge_inner, text="●", font=FONT_MONO_BOLD, bg=PANEL_ALT, fg=CYAN)
        self.status_dot.pack(side=tk.LEFT, padx=(0, 8))
        tk.Label(badge_inner, textvariable=self.status_var, font=FONT_MONO_BOLD, bg=PANEL_ALT, fg=TEXT).pack(
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
        tk.Label(scope_body, text="НЕ СКАНИРОВАТЬ ПАПКИ", font=FONT_HINT, bg=PANEL, fg=MUTED, anchor="w").pack(
            fill=tk.X, pady=(0, 6)
        )
        self._entry(scope_body, self.excluded_dirs_var).pack(fill=tk.X, ipady=6)
        tk.Label(scope_body, text="НЕ СКАНИРОВАТЬ ФАЙЛЫ", font=FONT_HINT, bg=PANEL, fg=MUTED, anchor="w").pack(
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
        tk.Label(controls, text="Порог энтропии", font=FONT_HINT, bg=PANEL, fg=MUTED).grid(
            row=0, column=0, sticky="w", padx=(0, 8)
        )
        self._spinbox(controls, self.entropy_threshold_var, 3.0, 6.5, 0.1, 5).grid(row=0, column=1)
        tk.Label(controls, text="Потоки", font=FONT_HINT, bg=PANEL, fg=MUTED).grid(
            row=0, column=2, sticky="w", padx=(18, 8)
        )
        self._spinbox(controls, self.workers_var, 1, 64, 1, 4).grid(row=0, column=3)

        # log -----------------------------------------------------------------
        log_panel, log_body = self._panel(root, "05", "АКТИВНОСТЬ", "Журнал сканирования появится здесь в реальном времени.")
        log_panel.grid(row=2, column=0, sticky="nsew", pady=(14, 12))
        log_body.pack_configure(fill=tk.BOTH, expand=True)
        tk.Label(
            log_body, text="$ tail -f audit.log", font=FONT_MONO, bg=PANEL, fg=MUTED, anchor="w"
        ).pack(fill=tk.X, pady=(0, 6))
        log_container = tk.Frame(log_body, bg=LOG_BG, highlightbackground=BORDER, highlightthickness=1)
        log_container.pack(fill=tk.BOTH, expand=True)
        self.log_text = tk.Text(
            log_container,
            wrap=tk.WORD,
            height=7,
            font=FONT_LOG,
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
        tk.Label(footer, text="> все проверки выполняются локально", bg=BG, fg=MUTED, font=FONT_HINT).pack(
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
            out_dir = self.output_dir_var.get().strip()
            out_path = Path(out_dir).resolve() if out_dir else target_path
            report = SecretScannerEngine(config).run(output_dir=out_path)
            self.last_report_path = out_path / "report.html"
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
        if self.last_report_path and self.last_report_path.exists():
            webbrowser.open(self.last_report_path.resolve().as_uri())
        else:
            messagebox.showerror("Отчёт не найден", "Файл report.html не найден. Проверьте, что формат HTML был включён.")


def launch_gui() -> None:
    app = SecretScannerGUI()
    app.mainloop()
