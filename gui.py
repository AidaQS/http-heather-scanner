import threading
import tkinter as tk
from tkinter import ttk, messagebox

from config import COLORS, APP_NAME, APP_VERSION

from scanner import scan

from analyzer import (
    analyze_security_headers,
    calculate_score,
    get_score_color,
    get_score_text
)


class HeaderScannerGUI:

    def __init__(self, root):

        self.root = root

        self.root.title(
            f"{APP_NAME} v{APP_VERSION}"
        )

        self.root.geometry(
            "1100x750"
        )

        self.root.minsize(
            900,
            650
        )

        self.root.configure(
            bg=COLORS["background"]
        )

        self.scanning = False

        self.placeholder_text = "Enter a URL"

        self.setup_styles()
        self.create_interface()


    # ==========================================
    # STYLES
    # ==========================================

    def setup_styles(self):

        style = ttk.Style()

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Treeview",
            background=COLORS["card"],
            foreground=COLORS["text"],
            fieldbackground=COLORS["card"],
            rowheight=40,
            borderwidth=0,
            font=("Segoe UI", 10)
        )

        style.configure(
            "Treeview.Heading",
            background=COLORS["secondary"],
            foreground=COLORS["text"],
            font=("Segoe UI", 10, "bold"),
            padding=8
        )

        style.map(
            "Treeview",
            background=[
                ("selected", COLORS["primary"])
            ]
        )


    # ==========================================
    # INTERFACE
    # ==========================================

    def create_interface(self):

        # --------------------------------------
        # HEADER
        # --------------------------------------

        header = tk.Frame(
            self.root,
            bg=COLORS["sidebar"],
            height=80
        )

        header.pack(fill="x")
        header.pack_propagate(False)


        title = tk.Label(
            header,
            text="🛡  HTTP Header Scanner",
            bg=COLORS["sidebar"],
            fg=COLORS["text"],
            font=("Segoe UI", 20, "bold")
        )

        title.pack(
            side="left",
            padx=25
        )


        version = tk.Label(
            header,
            text=f"v{APP_VERSION}",
            bg=COLORS["sidebar"],
            fg=COLORS["text_secondary"],
            font=("Segoe UI", 9)
        )

        version.pack(
            side="right",
            padx=25
        )


        # --------------------------------------
        # CONTENT
        # --------------------------------------

        content = tk.Frame(
            self.root,
            bg=COLORS["background"]
        )

        content.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=20
        )


        # --------------------------------------
        # URL CARD
        # --------------------------------------

        url_card = tk.Frame(
            content,
            bg=COLORS["card"],
            padx=20,
            pady=18
        )

        url_card.pack(
            fill="x",
            pady=(0, 20)
        )


        url_label = tk.Label(
            url_card,
            text="Website URL",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=("Segoe UI", 11, "bold")
        )

        url_label.pack(
            anchor="w"
        )


        input_frame = tk.Frame(
            url_card,
            bg=COLORS["card"]
        )

        input_frame.pack(
            fill="x",
            pady=(10, 0)
        )


        # --------------------------------------
        # URL ENTRY
        # --------------------------------------

        self.url_entry = tk.Entry(
            input_frame,
            bg=COLORS["input"],
            fg=COLORS["text_secondary"],
            insertbackground=COLORS["text"],
            relief="flat",
            font=("Segoe UI", 12)
        )

        self.url_entry.pack(
            side="left",
            fill="x",
            expand=True,
            ipady=10
        )


        # Add placeholder

        self.url_entry.insert(
            0,
            self.placeholder_text
        )


        # Focus events

        self.url_entry.bind(
            "<FocusIn>",
            self.remove_placeholder
        )

        self.url_entry.bind(
            "<FocusOut>",
            self.restore_placeholder
        )


        # Keyboard events

        self.url_entry.bind(
            "<Key>",
            self.handle_keypress
        )


        # Press ENTER to scan

        self.url_entry.bind(
            "<Return>",
            lambda event: self.start_scan()
        )


        # --------------------------------------
        # CLEAR BUTTON
        # --------------------------------------

        self.clear_button = tk.Button(
            input_frame,
            text="✕  CLEAR",
            bg=COLORS["secondary"],
            fg=COLORS["text"],
            activebackground=COLORS["card_light"],
            activeforeground=COLORS["text"],
            relief="flat",
            borderwidth=0,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
            command=self.clear_url
        )

        self.clear_button.pack(
            side="left",
            padx=(10, 0),
            ipadx=10,
            ipady=8
        )


        # --------------------------------------
        # SCAN BUTTON
        # --------------------------------------

        self.scan_button = tk.Button(
            input_frame,
            text="🔍  SCAN",
            bg=COLORS["primary"],
            fg="white",
            activebackground=COLORS["primary_hover"],
            activeforeground="white",
            relief="flat",
            borderwidth=0,
            cursor="hand2",
            font=("Segoe UI", 11, "bold"),
            command=self.start_scan
        )

        self.scan_button.pack(
            side="left",
            padx=(10, 0),
            ipadx=18,
            ipady=8
        )


        # --------------------------------------
        # CANCEL BUTTON
        # --------------------------------------

        self.cancel_button = tk.Button(
            input_frame,
            text="✕  CANCEL",
            bg=COLORS["danger"],
            fg="white",
            activebackground="#D94452",
            activeforeground="white",
            relief="flat",
            borderwidth=0,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
            command=self.cancel_scan,
            state="disabled"
        )

        self.cancel_button.pack(
            side="left",
            padx=(8, 0),
            ipadx=12,
            ipady=8
        )


        # --------------------------------------
        # SUMMARY
        # --------------------------------------

        summary = tk.Frame(
            content,
            bg=COLORS["background"]
        )

        summary.pack(
            fill="x",
            pady=(0, 20)
        )


        self.status_card = self.create_info_card(
            summary,
            "STATUS",
            "-"
        )

        self.status_card.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 10)
        )


        self.score_card = self.create_info_card(
            summary,
            "SECURITY SCORE",
            "-"
        )

        self.score_card.pack(
            side="left",
            fill="both",
            expand=True,
            padx=10
        )


        self.url_card = self.create_info_card(
            summary,
            "FINAL URL",
            "-"
        )

        self.url_card.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(10, 0)
        )


        # --------------------------------------
        # RESULTS
        # --------------------------------------

        results_card = tk.Frame(
            content,
            bg=COLORS["card"]
        )

        results_card.pack(
            fill="both",
            expand=True
        )


        results_title = tk.Label(
            results_card,
            text="🔐  Security Headers",
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=("Segoe UI", 12, "bold"),
            anchor="w"
        )

        results_title.pack(
            fill="x",
            padx=20,
            pady=15
        )


        columns = (
            "header",
            "status",
            "severity",
            "value"
        )


        self.tree = ttk.Treeview(
            results_card,
            columns=columns,
            show="headings"
        )


        self.tree.heading(
            "header",
            text="Header"
        )

        self.tree.heading(
            "status",
            text="Status"
        )

        self.tree.heading(
            "severity",
            text="Severity"
        )

        self.tree.heading(
            "value",
            text="Value"
        )


        self.tree.column(
            "header",
            width=260
        )

        self.tree.column(
            "status",
            width=130,
            anchor="center"
        )

        self.tree.column(
            "severity",
            width=120,
            anchor="center"
        )

        self.tree.column(
            "value",
            width=420
        )


        self.tree.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=(0, 20)
        )


        self.tree.tag_configure(
            "ok",
            foreground=COLORS["success"]
        )

        self.tree.tag_configure(
            "missing",
            foreground=COLORS["danger"]
        )


        # --------------------------------------
        # FOOTER
        # --------------------------------------

        self.footer = tk.Label(
            self.root,
            text="Ready to scan",
            bg=COLORS["sidebar"],
            fg=COLORS["text_secondary"],
            anchor="w",
            padx=20,
            font=("Segoe UI", 9)
        )

        self.footer.pack(
            fill="x",
            ipady=8
        )


    # ==========================================
    # PLACEHOLDER
    # ==========================================

    def remove_placeholder(self, event=None):

        if self.url_entry.get() == self.placeholder_text:

            self.url_entry.delete(
                0,
                tk.END
            )

            self.url_entry.config(
                fg=COLORS["text"]
            )


    def restore_placeholder(self, event=None):

        if not self.url_entry.get().strip():

            self.url_entry.insert(
                0,
                self.placeholder_text
            )

            self.url_entry.config(
                fg=COLORS["text_secondary"]
            )


    def handle_keypress(self, event=None):

        if self.url_entry.get() == self.placeholder_text:

            self.url_entry.delete(
                0,
                tk.END
            )

            self.url_entry.config(
                fg=COLORS["text"]
            )


    # ==========================================
    # CLEAR URL
    # ==========================================

    def clear_url(self):

        if self.scanning:
            return


        self.url_entry.delete(
            0,
            tk.END
        )


        self.url_entry.insert(
            0,
            self.placeholder_text
        )


        self.url_entry.config(
            fg=COLORS["text_secondary"]
        )


        self.clear_results()


        self.footer.config(
            text="Ready to scan"
        )


        self.url_entry.focus()


    # ==========================================
    # INFO CARD
    # ==========================================

    def create_info_card(
        self,
        parent,
        title,
        value
    ):

        card = tk.Frame(
            parent,
            bg=COLORS["card"],
            padx=18,
            pady=15
        )


        title_label = tk.Label(
            card,
            text=title,
            bg=COLORS["card"],
            fg=COLORS["text_secondary"],
            font=("Segoe UI", 9, "bold")
        )

        title_label.pack(
            anchor="w"
        )


        value_label = tk.Label(
            card,
            text=value,
            bg=COLORS["card"],
            fg=COLORS["text"],
            font=("Segoe UI", 15, "bold"),
            anchor="w"
        )

        value_label.pack(
            anchor="w",
            pady=(5, 0)
        )


        card.value_label = value_label

        return card


    # ==========================================
    # START SCAN
    # ==========================================

    def start_scan(self):

        if self.scanning:
            return


        url = self.url_entry.get().strip()


        if not url or url == self.placeholder_text:

            messagebox.showwarning(
                "URL",
                "Please enter a website URL"
            )

            self.url_entry.focus()

            return


        self.scanning = True


        self.scan_button.config(
            state="disabled",
            text="⏳  SCANNING..."
        )


        self.clear_button.config(
            state="disabled"
        )


        self.cancel_button.config(
            state="normal"
        )


        self.footer.config(
            text="Connecting to website..."
        )


        self.clear_results()


        thread = threading.Thread(
            target=self.perform_scan,
            args=(url,),
            daemon=True
        )

        thread.start()


    # ==========================================
    # PERFORM SCAN
    # ==========================================

    def perform_scan(self, url):

        try:

            result = scan(url)

            self.root.after(
                0,
                lambda: self.display_results(result)
            )

        except Exception as error:

            self.root.after(
                0,
                lambda: self.show_scan_error(error)
            )


    # ==========================================
    # CANCEL
    # ==========================================

    def cancel_scan(self):

        if not self.scanning:
            return


        self.scanning = False


        self.scan_button.config(
            state="normal",
            text="🔍  SCAN"
        )


        self.clear_button.config(
            state="normal"
        )


        self.cancel_button.config(
            state="disabled"
        )


        self.footer.config(
            text="Scan cancelled."
        )


    # ==========================================
    # ERROR
    # ==========================================

    def show_scan_error(self, error):

        if not self.scanning:
            return


        self.scanning = False


        self.scan_button.config(
            state="normal",
            text="🔍  SCAN"
        )


        self.clear_button.config(
            state="normal"
        )


        self.cancel_button.config(
            state="disabled"
        )


        self.footer.config(
            text="Scan failed."
        )


        messagebox.showerror(
            "Scan Error",
            str(error)
        )


    # ==========================================
    # DISPLAY RESULTS
    # ==========================================

    def display_results(self, result):

        if not self.scanning:
            return


        self.scanning = False


        status = result["status"]

        final_url = result["url"]

        headers = result["headers"]


        # STATUS

        self.status_card.value_label.config(
            text=str(status)
        )


        if 200 <= status < 300:

            self.status_card.value_label.config(
                fg=COLORS["success"]
            )

        elif 300 <= status < 400:

            self.status_card.value_label.config(
                fg=COLORS["warning"]
            )

        else:

            self.status_card.value_label.config(
                fg=COLORS["danger"]
            )


        # FINAL URL

        self.url_card.value_label.config(
            text=final_url
        )


        # ANALYZE HEADERS

        analysis = analyze_security_headers(
            headers
        )


        score = calculate_score(
            analysis
        )


        score_color = get_score_color(
            score
        )


        self.score_card.value_label.config(
            text=f"{score}/100",
            fg=score_color
        )


        # CLEAR TABLE

        for item in self.tree.get_children():

            self.tree.delete(item)


        # INSERT RESULTS

        for item in analysis:

            if item["present"]:

                status_text = "✓ PRESENT"

                tag = "ok"

            else:

                status_text = "✗ MISSING"

                tag = "missing"


            self.tree.insert(
                "",
                "end",
                values=(
                    item["name"],
                    status_text,
                    item["severity"],
                    item["value"] or "-"
                ),
                tags=(tag,)
            )


        # ENABLE BUTTONS

        self.scan_button.config(
            state="normal",
            text="🔍  SCAN"
        )


        self.clear_button.config(
            state="normal"
        )


        self.cancel_button.config(
            state="disabled"
        )


        self.footer.config(
            text=(
                f"Scan completed · "
                f"{get_score_text(score)}"
            )
        )


    # ==========================================
    # CLEAR RESULTS
    # ==========================================

    def clear_results(self):

        for item in self.tree.get_children():

            self.tree.delete(item)


        self.status_card.value_label.config(
            text="-",
            fg=COLORS["text"]
        )


        self.score_card.value_label.config(
            text="-",
            fg=COLORS["text"]
        )


        self.url_card.value_label.config(
            text="-",
            fg=COLORS["text"]
        )


# ==========================================
# APPLICATION
# ==========================================

def create_app():

    root = tk.Tk()

    HeaderScannerGUI(root)

    root.mainloop()