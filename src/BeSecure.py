import os
import shutil
import json
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import time

# -------------------------
# Directories and Files
# -------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
TRASH_DIR = os.path.join(BASE_DIR, "trash")
ORIGINAL_PATH_DB = os.path.join(QUARANTINE_DIR, "restore_paths.json")
DEFAULT_SIGNATURE_FILE = os.path.join(BASE_DIR, "default_signatures.txt")

SUSPICIOUS_EXTENSIONS = (".exe", ".bat", ".cmd", ".ps1", ".vbs")

INFECTED_METADATA_FILE = os.path.join(BASE_DIR, "infected_metadata.json")


# Ensure required folders exist
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(TRASH_DIR, exist_ok=True)

# Initialize restore paths database if missing
if not os.path.exists(ORIGINAL_PATH_DB):
    with open(ORIGINAL_PATH_DB, "w") as f:
        json.dump({}, f, indent=4)


# -------------------------
# Antivirus GUI Class
# -------------------------
class AntivirusDemo:
    def __init__(self, root):
        self.root = root
        root.title("BeSecure - Stand with Palestine 🍉")
        root.geometry("1000x650")

        # State variables
        self.selected_dir = None
        self.status_var = tk.StringVar(value="Idle")
        self.sig_count_var = tk.StringVar(value="Signatures Loaded: 0")
        self.pre_scan_action = tk.StringVar(value="None")

        self.restore_db = {}
        self.signatures = set()

        # Initialize
        self.load_quarantine_db()
        self.create_gui()
        self.load_signatures()

    # -------------------------
    # GUI Helpers
    # -------------------------
    def create_gui(self):
        top_frame = tk.Frame(self.root)
        top_frame.pack(pady=8, padx=8, anchor="w")

        # Buttons
        tk.Button(top_frame, text="Select Folder", width=14, command=self.select_folder).grid(row=0, column=0, padx=4)
        tk.Button(top_frame, text="Scan Folder", width=14, command=self.start_scan).grid(row=0, column=1, padx=4)
        tk.Button(top_frame, text="Quarantine Selected", width=18, command=self.quarantine_selected).grid(row=0, column=2, padx=4)
        tk.Button(top_frame, text="Delete Selected", width=14, command=self.delete_selected).grid(row=0, column=3, padx=4)
        tk.Button(top_frame, text="Restore Selected", width=15, command=self.restore_selected).grid(row=0, column=4, padx=4)

        # Action on detect
        tk.Label(top_frame, text="Action on Detect:").grid(row=1, column=0, sticky="e")
        tk.OptionMenu(top_frame, self.pre_scan_action, "None", "Quarantine", "Delete").grid(row=1, column=1, sticky="w")

        # Status and signature count
        tk.Label(self.root, textvariable=self.status_var).pack()
        tk.Label(self.root, textvariable=self.sig_count_var).pack()

        # Log box
        self.log_box = tk.Text(self.root, height=10, width=120)
        self.log_box.pack(pady=5)

        # Results listbox
        self.results_list = tk.Listbox(self.root, width=120, height=15)
        self.results_list.pack(padx=8, pady=5, fill="both", expand=True)

    def log(self, msg):
        """Append message to the log box."""
        self.log_box.insert(tk.END, msg + "\n")
        self.log_box.see(tk.END)

    def update_list_item(self, index, new_text, color="black"):
        """Update a listbox item with new text and color."""
        self.results_list.delete(index)
        self.results_list.insert(index, new_text)
        self.results_list.itemconfig(index, fg=color)

    def extract_real_path(self, list_text):
        """Get original file path from listbox text (remove status tags)."""
        return list_text.replace("[QUARANTINED] ", "").replace("[TRASHED] ", "")

    # -------------------------
    # Signature Handling
    # -------------------------
    def load_signatures(self):
        if not os.path.exists(DEFAULT_SIGNATURE_FILE):
            with open(DEFAULT_SIGNATURE_FILE, "w") as f:
                f.write("# Example SHA256 hashes\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")

        with open(DEFAULT_SIGNATURE_FILE, "r") as f:
            self.signatures = {line.strip() for line in f if line.strip() and not line.startswith("#")}

        self.sig_count_var.set(f"Signatures Loaded: {len(self.signatures)}")
        self.log(f"[INFO] Loaded {len(self.signatures)} hash signatures")

    # -------------------------
    # Folder Selection
    # -------------------------
    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.selected_dir = folder
            self.log(f"[SELECTED] {folder}")

    # -------------------------
    # Hash Calculation
    # -------------------------
    def calculate_hash(self, filepath):
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()

    # -------------------------
    # Behavior Indicators
    # -------------------------
    def behavior_flags(self, filepath):
        name = filepath.lower()
        flags = []
        if "powershell" in name:
            flags.append("PowerShell usage")
        if "cmd" in name:
            flags.append("CMD execution")
        if "calc" in name:
            flags.append("System binary abuse")
        if "browser" in name or "chrome" in name or "website" in name:
            flags.append("Browser launch")
        if "warning" in name:
            flags.append("Warning popup")
        if "taskmgr" in name:
            flags.append("Launches Task Manager")
        if "camera" in name:
            flags.append("Accesses camera")

        return flags

    # -------------------------
    # Scanning
    # -------------------------
    def start_scan(self):
        if not self.selected_dir:
            messagebox.showerror("Error", "Select a folder first")
            return
        threading.Thread(target=self.scan_folder, daemon=True).start()

    def scan_folder(self):
        self.status_var.set("Scanning...")
        self.results_list.delete(0, tk.END)
        self.log("--- Scan started ---")

        for root_dir, _, files in os.walk(self.selected_dir):
            if QUARANTINE_DIR in root_dir or TRASH_DIR in root_dir:
                continue

            for file in files:
                if not file.lower().endswith(SUSPICIOUS_EXTENSIONS):
                    continue

                path = os.path.join(root_dir, file)
                self.log(f"Scanning: {path}")

                try:
                    file_hash = self.calculate_hash(path)
                    infected = file_hash in self.signatures
                except Exception:
                    infected = False

                flags = self.behavior_flags(path)
                idx = self.results_list.size()
                self.results_list.insert(tk.END, path)

                if infected:
                    self.results_list.itemconfig(idx, fg="red")
                    self.log(f"[INFECTED] {path}")
                    if flags:
                        self.log(f"[BEHAVIOR] {', '.join(flags)}")

                    # Save metadata of infected file
                    self.save_infected_metadata(path, file_hash, flags)

                    if self.pre_scan_action.get() == "Quarantine":
                        self.quarantine_file(path)
                    elif self.pre_scan_action.get() == "Delete":
                        self.trash_file(path)
                else:
                    self.results_list.itemconfig(idx, fg="green")

        self.status_var.set("Scan Completed")
        self.log("--- Scan finished ---")

    def save_infected_metadata(self, filepath, file_hash, flags):
        """Save infected file metadata to a JSON file."""
        metadata = {
            "name": os.path.basename(filepath),
            "path": filepath,
            "size_bytes": os.path.getsize(filepath),
            "last_modified": time.ctime(os.path.getmtime(filepath)),
            "sha256": file_hash,
            "behavior_flags": flags
        }

        # Load existing metadata if exists
        if os.path.exists(INFECTED_METADATA_FILE):
            try:
                with open(INFECTED_METADATA_FILE, "r") as f:
                    data = json.load(f)
            except Exception:
                data = []
        else:
            data = []

        data.append(metadata)

        # Save updated metadata
        with open(INFECTED_METADATA_FILE, "w") as f:
            json.dump(data, f, indent=4)


    # -------------------------
    # Quarantine / Trash / Restore
    # -------------------------
    def load_quarantine_db(self):
        try:
            with open(ORIGINAL_PATH_DB, "r") as f:
                self.restore_db = json.load(f)
        except Exception:
            self.restore_db = {}

    def save_quarantine_db(self):
        with open(ORIGINAL_PATH_DB, "w") as f:
            json.dump(self.restore_db, f, indent=4)

    def quarantine_file(self, filepath):
        name = os.path.basename(filepath)
        dest = os.path.join(QUARANTINE_DIR, name)
        shutil.move(filepath, dest)
        self.restore_db[name] = filepath
        self.save_quarantine_db()
        self.log(f"[QUARANTINED] {name}")

    def trash_file(self, filepath):
        name = os.path.basename(filepath)
        dest = os.path.join(TRASH_DIR, name)

        if os.path.exists(dest):
            os.remove(dest)

        shutil.move(filepath, dest)
        self.log(f"[TRASHED] {name}")

    def quarantine_selected(self):
        sel = self.results_list.curselection()
        if not sel:
            return

        idx = sel[0]
        path = self.extract_real_path(self.results_list.get(idx))

        if os.path.exists(path):
            self.quarantine_file(path)
            self.update_list_item(idx, f"[QUARANTINED] {path}", color="orange")

    def delete_selected(self):
        sel = self.results_list.curselection()
        if not sel:
            return

        idx = sel[0]
        path = self.extract_real_path(self.results_list.get(idx))
        name = os.path.basename(path)

        # Case 1: file in original location
        if os.path.exists(path):
            self.trash_file(path)
            self.update_list_item(idx, f"[TRASHED] {path}", color="gray")
            return

        # Case 2: file is quarantined
        quarantined_path = os.path.join(QUARANTINE_DIR, name)
        if os.path.exists(quarantined_path):
            dest = os.path.join(TRASH_DIR, name)
            if os.path.exists(dest):
                os.remove(dest)
            shutil.move(quarantined_path, dest)

            if name in self.restore_db:
                del self.restore_db[name]
                self.save_quarantine_db()

            self.log(f"[TRASHED] {name}")
            self.update_list_item(idx, f"[TRASHED] {path}", color="gray")
            return

        messagebox.showwarning("Delete failed", "File not found.")

    def restore_selected(self):
        sel = self.results_list.curselection()
        if not sel:
            return

        idx = sel[0]
        name = os.path.basename(self.extract_real_path(self.results_list.get(idx)))

        if name in self.restore_db:
            src = os.path.join(QUARANTINE_DIR, name)
            dst = self.restore_db[name]

            if not os.path.exists(src):
                messagebox.showwarning("Restore failed", "Quarantined file missing.")
                return

            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.move(src, dst)

            del self.restore_db[name]
            self.save_quarantine_db()
            self.log(f"[RESTORED] {name}")

            # Update listbox to show restored file in green
            self.update_list_item(idx, dst, color="green")


# -------------------------
# Run App
# -------------------------
def main():
    root = tk.Tk()
    AntivirusDemo(root)
    root.mainloop()


if __name__ == "__main__":
    main()
