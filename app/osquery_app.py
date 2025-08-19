import csv
import json
import os
import platform
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_TITLE = "osqueryi Runner (Improved GUI)"
DEFAULT_QUERY = "SELECT * FROM os_version;"

EXAMPLE_QUERIES = {
    "OS version": "SELECT * FROM os_version;",
    "Logged-in users": "SELECT * FROM logged_in_users;",
    "Active user’s groups (by uid join)": """
SELECT liu.username, ug.groupname
FROM logged_in_users liu
JOIN user_groups ug
  ON liu.uid = ug.uid
WHERE liu.type = 'active';
""".strip(),
    "Process by name (edit LIKE)": """
SELECT name, pid, path, start_time
FROM processes
WHERE name LIKE '%zoom%';
""".strip(),
    "Listening ports": """
SELECT lp.address, lp.port, lp.protocol, lp.state, p.pid, p.name, p.path
FROM listening_ports lp
LEFT JOIN processes p USING (pid)
ORDER BY lp.port;
""".strip(),
    "Chrome extensions": "SELECT * FROM chrome_extensions;",
}


def which_osqueryi():
    env_path = os.environ.get("OSQUERYI_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path
    path = shutil.which("osqueryi")
    if path:
        return path
    common = [
        "/usr/local/bin/osqueryi",
        "/opt/osquery/bin/osqueryi",
        "C:\\Program Files\\osquery\\osqueryi.exe",
        "C:\\ProgramData\\osquery\\osqueryi.exe",
    ]
    for p in common:
        if os.path.isfile(p):
            return p
    return None


class OsqueryGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1000x640")
        self.minsize(800, 520)

        self.osquery_path_var = tk.StringVar(value=which_osqueryi() or "")
        self.timeout_var = tk.IntVar(value=60)
        self.query_text = None
        self.tree = None
        self.status_var = tk.StringVar(value="Ready.")
        self.last_rows = []
        self.result_queue = queue.Queue()
        self.worker_thread = None
        self.current_proc = None
        self._sort_state = {"col": None, "reverse": False}

        self._build_ui()

    # -------------------- UI --------------------
    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(4, weight=1)

        # Top: osqueryi path
        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 6))
        top.columnconfigure(1, weight=1)

        ttk.Label(top, text="osqueryi path:").grid(
            row=0, column=0, sticky="w", padx=(0, 6)
        )
        path_entry = ttk.Entry(top, textvariable=self.osquery_path_var)
        path_entry.grid(row=0, column=1, sticky="ew")
        ttk.Button(top, text="Browse…", command=self._browse_osqueryi).grid(
            row=0, column=2, padx=(6, 0)
        )

        # Examples dropdown
        ex_frame = ttk.Frame(self)
        ex_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 6))
        ex_frame.columnconfigure(1, weight=1)

        ttk.Label(ex_frame, text="Examples:").grid(row=0, column=0, sticky="w")
        self.example_var = tk.StringVar(value="OS version")
        ex_combo = ttk.Combobox(
            ex_frame,
            textvariable=self.example_var,
            values=list(EXAMPLE_QUERIES.keys()),
            state="readonly",
            width=40,
        )
        ex_combo.grid(row=0, column=1, sticky="w")
        ttk.Button(ex_frame, text="Load Example", command=self._load_example).grid(
            row=0, column=2, padx=(6, 0)
        )

        # Query text area
        q_frame = ttk.Frame(self)
        q_frame.grid(row=2, column=0, sticky="nsew", padx=10)
        q_frame.columnconfigure(0, weight=1)
        ttk.Label(q_frame, text="SQL:").grid(row=0, column=0, sticky="w", pady=(0, 4))
        self.query_text = tk.Text(q_frame, height=8, undo=True, wrap="none")
        self.query_text.grid(row=1, column=0, sticky="nsew")
        self.query_text.insert("1.0", DEFAULT_QUERY)

        q_scroll_y = ttk.Scrollbar(
            q_frame, orient="vertical", command=self.query_text.yview
        )
        q_scroll_y.grid(row=1, column=1, sticky="ns")
        self.query_text.configure(yscrollcommand=q_scroll_y.set)

        # Buttons and timeout
        btn_bar = ttk.Frame(self)
        btn_bar.grid(row=3, column=0, sticky="ew", padx=10, pady=6)
        ttk.Label(btn_bar, text="Timeout (s):").pack(side="left")
        ttk.Spinbox(
            btn_bar, from_=5, to=600, textvariable=self.timeout_var, width=5
        ).pack(side="left", padx=(4, 8))

        self.run_button = ttk.Button(
            btn_bar, text="Run (Cmd/Ctrl+Enter)", command=self.run_query
        )
        self.run_button.pack(side="left")
        self.cancel_button = ttk.Button(btn_bar, text="Cancel", command=self._cancel_query)
        self.cancel_button.pack(side="left", padx=(6, 0))
        self.cancel_button["state"] = "disabled"

        ttk.Button(btn_bar, text="Export CSV", command=self.export_csv).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(btn_bar, text="Copy JSON", command=self.copy_json).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(btn_bar, text="Clear Results", command=self.clear_results).pack(
            side="left", padx=(6, 0)
        )

        # Results treeview
        tree_frame = ttk.Frame(self)
        tree_frame.grid(row=4, column=0, sticky="nsew", padx=10)
        self.rowconfigure(4, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(tree_frame, columns=(), show="headings")
        self.tree.grid(row=0, column=0, sticky="nsew")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        vsb.grid(row=0, column=1, sticky="ns")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        hsb.grid(row=1, column=0, sticky="ew")
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # Status bar
        status = ttk.Frame(self)
        status.grid(row=5, column=0, sticky="ew", padx=10, pady=(4, 10))
        status.columnconfigure(0, weight=1)
        ttk.Label(status, textvariable=self.status_var).grid(
            row=0, column=0, sticky="w"
        )

        # Keybind
        if platform.system() == "Darwin":
            self.bind_all("<Command-Return>", lambda e: self.run_query())
        else:
            self.bind_all("<Control-Return>", lambda e: self.run_query())

    # -------------------- Actions --------------------
    def _browse_osqueryi(self):
        initialdir = (
            "/usr/local/bin" if os.name != "nt" else "C:\\Program Files\\osquery"
        )
        filetypes = [("osqueryi", "osqueryi*"), ("All files", "*.*")]
        path = filedialog.askopenfilename(
            title="Select osqueryi", initialdir=initialdir, filetypes=filetypes
        )
        if path:
            self.osquery_path_var.set(path)

    def _load_example(self):
        name = self.example_var.get()
        sql = EXAMPLE_QUERIES.get(name, DEFAULT_QUERY)
        self.query_text.delete("1.0", "end")
        self.query_text.insert("1.0", sql.strip())

    def _validate_osqueryi(self):
        path = self.osquery_path_var.get().strip()
        if not path:
            messagebox.showerror(
                "osqueryi not found", "Please set the path to osqueryi."
            )
            return None
        if not os.path.isfile(path):
            messagebox.showerror("Invalid path", f"File not found:\n{path}")
            return None
        return path

    def run_query(self):
        # Prevent re-entry
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showinfo("Busy", "A query is already running.")
            return

        path = self._validate_osqueryi()
        if not path:
            return

        sql = self.query_text.get("1.0", "end").strip()
        if not sql:
            messagebox.showwarning("Empty query", "Please enter a SQL query.")
            return

        # Kick off worker thread
        self.status_var.set("Running…")
        self.last_rows = []
        self.result_queue = queue.Queue()
        self.worker_thread = threading.Thread(
            target=self._run_query_worker, args=(path, sql, int(self.timeout_var.get())), daemon=True
        )
        self.worker_thread.start()
        self.run_button["state"] = "disabled"
        self.cancel_button["state"] = "normal"
        self.after(150, self._poll_worker)

    def _run_query_worker(self, osq_path, sql, timeout_s):
        start = time.time()
        try:
            # Use --json for structured output. Popen allows cancellation.
            cmd = [osq_path, "--json", sql]
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            self.current_proc = proc
            try:
                stdout, stderr = proc.communicate(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
                elapsed = (time.time() - start) * 1000.0
                self.result_queue.put(
                    {"type": "error", "message": f"Query timed out after {timeout_s}s.", "elapsed_ms": elapsed}
                )
                return
            finally:
                self.current_proc = None

            elapsed = (time.time() - start) * 1000.0
            if proc.returncode != 0:
                msg = stderr.strip() or f"osqueryi returned code {proc.returncode}"
                self.result_queue.put({"type": "error", "message": msg, "elapsed_ms": elapsed})
                return

            stdout = stdout.strip()
            if not stdout:
                self.result_queue.put({"type": "result", "rows": [], "elapsed_ms": elapsed})
                return

            # Best-effort extract first JSON array if extra text present
            try:
                data = json.loads(stdout)
            except Exception:
                m = re.search(r"(\[.*\])", stdout, re.DOTALL)
                if m:
                    try:
                        data = json.loads(m.group(1))
                    except Exception as e:
                        self.result_queue.put(
                            {
                                "type": "error",
                                "message": f"Failed to parse JSON output:\n{e}\n\nRaw output (truncated):\n{stdout[:1000]}",
                                "elapsed_ms": elapsed,
                            }
                        )
                        return
                else:
                    self.result_queue.put(
                        {
                            "type": "error",
                            "message": f"Unexpected output; not valid JSON.\nRaw output (truncated):\n{stdout[:1000]}",
                            "elapsed_ms": elapsed,
                        }
                    )
                    return

            if not isinstance(data, list):
                self.result_queue.put(
                    {
                        "type": "error",
                        "message": "Parsed JSON is not a list of rows.",
                        "elapsed_ms": elapsed,
                    }
                )
                return

            self.result_queue.put({"type": "result", "rows": data, "elapsed_ms": elapsed})
        except FileNotFoundError:
            self.current_proc = None
            self.result_queue.put(
                {"type": "error", "message": "osqueryi not found. Check the path.", "elapsed_ms": 0}
            )
        except Exception as e:
            self.current_proc = None
            self.result_queue.put({"type": "error", "message": str(e), "elapsed_ms": 0})

    def _cancel_query(self):
        if self.current_proc:
            try:
                self.current_proc.kill()
            except Exception:
                pass
            self.current_proc = None
            self.status_var.set("Cancelled.")
            self.run_button["state"] = "normal"
            self.cancel_button["state"] = "disabled"

    def _poll_worker(self):
        # show running indicator while thread is alive
        try:
            item = self.result_queue.get_nowait()
        except queue.Empty:
            if self.worker_thread and self.worker_thread.is_alive():
                # animate dots
                cur = self.status_var.get()
                if not cur.startswith("Running"):
                    self.status_var.set("Running.")
                else:
                    if cur.endswith("..."):
                        self.status_var.set("Running")
                    else:
                        self.status_var.set(cur + ".")
                self.after(150, self._poll_worker)
            else:
                self.status_var.set("Ready.")
                self.run_button["state"] = "normal"
                self.cancel_button["state"] = "disabled"
            return

        if item["type"] == "error":
            self.status_var.set(f"Error ({int(item.get('elapsed_ms', 0))} ms)")
            messagebox.showerror("osqueryi error", item["message"])
        else:
            # Display results
            self.last_rows = item["rows"]
            self._display_rows(self.last_rows)
            n = len(self.last_rows)
            self.status_var.set(f"{n} row(s) in {int(item.get('elapsed_ms', 0))} ms")
        # finalize UI
        self.run_button["state"] = "normal"
        self.cancel_button["state"] = "disabled"

    def _display_rows(self, rows):
        # Determine columns (union of keys)
        cols = set()
        for r in rows:
            if isinstance(r, dict):
                cols.update(r.keys())
        cols = sorted(cols)

        # Reset tree columns
        self.tree["columns"] = cols
        for c in cols:
            # set heading with clickable sort
            self.tree.heading(c, text=c, command=lambda _c=c: self._sort_tree(_c))
            # Rough width based on header and sample of data
            max_chars = max(len(c), 12)
            sample_count = min(len(rows), 200)
            if sample_count:
                for r in rows[:sample_count]:
                    v = r.get(c, "")
                    max_chars = max(max_chars, len(str(v)))
            width = min(12 + 7 * max_chars, 600)
            self.tree.column(c, width=width, stretch=True, anchor="w")

        # Clear existing
        for iid in self.tree.get_children():
            self.tree.delete(iid)

        # Insert rows
        for r in rows:
            values = [str(r.get(c, "")) for c in cols]
            self.tree.insert("", "end", values=values)

        # Reset sort state when new data loads
        self._sort_state = {"col": None, "reverse": False}

    def _sort_tree(self, col):
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        # try numeric sort if possible
        def try_num(x):
            try:
                return float(x)
            except Exception:
                return x.lower() if isinstance(x, str) else x

        reverse = False
        if self._sort_state["col"] == col:
            reverse = not self._sort_state["reverse"]
        else:
            reverse = False
        data.sort(key=lambda t: try_num(t[0]), reverse=reverse)
        for index, (_, k) in enumerate(data):
            self.tree.move(k, "", index)
        self._sort_state["col"] = col
        self._sort_state["reverse"] = reverse

    def export_csv(self):
        if not self.last_rows:
            messagebox.showinfo("No data", "Run a query first.")
            return

        dest = filedialog.asksaveasfilename(
            title="Save results as CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"osquery_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        )
        if not dest:
            return

        cols = list(self.tree["columns"])
        try:
            with open(dest, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
                writer.writeheader()
                for row in self.last_rows:
                    writer.writerow({k: row.get(k, "") for k in cols})
            messagebox.showinfo(
                "Saved", f"Exported {len(self.last_rows)} row(s) to:\n{dest}"
            )
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def copy_json(self):
        data = self.last_rows if self.last_rows else []
        payload = json.dumps(data, indent=2)
        try:
            self.clipboard_clear()
            self.clipboard_append(payload)
            self.update()  # now it stays on clipboard after window closes
            messagebox.showinfo(
                "Copied", f"Copied {len(data)} row(s) as JSON to clipboard."
            )
        except Exception as e:
            messagebox.showerror("Copy failed", str(e))

    def clear_results(self):
        self.last_rows = []
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.tree["columns"] = ()
        self.status_var.set("Results cleared.")

def main():
    app = OsqueryGUI()
    if not app.osquery_path_var.get():
        app.after(
            250,
            lambda: messagebox.showwarning(
                "osqueryi not found",
                "osqueryi was not found in PATH. Set the path at the top-left or install osquery:\n"
                "https://osquery.io/downloads",
            ),
        )
    app.mainloop()


if __name__ == "__main__":
    main()
