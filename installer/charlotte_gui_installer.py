# C-H-A-R-L-O-T-T-E GUI Installer
# This script provides a GUI installer for C-H-A-R-L-O-T-T-E, allowing
# users to install various security tools.
# It includes options for reverse engineering, recon, vulnscan, and exploitation tools.
# ==========================================================================================

# IMPORTS
import sys
import os
import subprocess
import webbrowser
from tkinter import Tk, Label, Button, messagebox, Toplevel

# ==========================================================================================
# FUNCTION: launch_metasploit_plugin()
# Launches CHARLOTTE's Metasploit plugin via subprocess
# ==========================================================================================
def launch_metasploit_plugin():
    try:
        subprocess.Popen([
            sys.executable,
            os.path.join(os.path.dirname(__file__), "..", "plugins", "exploitation", "metasploit_plugin.py")
        ])
    except Exception as e:
        messagebox.showerror("Error", f"Failed to launch Metasploit plugin: {e}")

# ==========================================================================================
# FUNCTION: open_ghidra_installer()
# Launches Ghidra installer script
# ==========================================================================================
def open_ghidra_installer():
    subprocess.Popen([sys.executable, os.path.join(os.path.dirname(__file__), "ghidra", "ghidra_installer.py")])

# ==========================================================================================
# FUNCTION: open_binary_ninja_installer()
# Launches Binary Ninja installer script
# ==========================================================================================
def open_binary_ninja_installer():
    subprocess.Popen([sys.executable, os.path.join(os.path.dirname(__file__), "binary_ninja", "binary_ninja_installer.py")])

# ==========================================================================================
# FUNCTION: open_zap_installer()
# Launches OWASP ZAP installer script
# ==========================================================================================
def open_zap_installer():
    subprocess.Popen([sys.executable, os.path.join(os.path.dirname(__file__), "owasp_zap", "zap_installer.py")])

# ==========================================================================================
# FUNCTION: open_jdk_download()
# Opens JDK 21 download page in browser
# ==========================================================================================
def open_jdk_download():
    webbrowser.open("https://adoptium.net/temurin/releases")

# ==========================================================================================
# FUNCTION: show_about()
# Displays CHARLOTTE information
# ==========================================================================================
def show_about():
    messagebox.showinfo("About", "C-H-A-R-L-O-T-T-E GUI Installer\nModular security framework\nhttps://github.com/Core-Creates/C-H-A-R-L-O-T-T-E")

# ==========================================================================================
# FUNCTION: show_re_window()
# Reverse engineering tool window (Ghidra, Binary Ninja, etc.)
# ==========================================================================================
def show_re_window(parent):
    win = Toplevel(parent)
    win.title("Reverse Engineering Installers")
    win.geometry("350x220")
    Label(win, text="Reverse Engineering Tools", font=("Arial", 14, "bold")).pack(pady=10)
    Button(win, text="Install Ghidra (Headless)", width=30, command=open_ghidra_installer).pack(pady=5)
    Button(win, text="Install Binary Ninja (Free)", width=30, command=open_binary_ninja_installer).pack(pady=5)
    Button(win, text="Back", width=30, command=win.destroy).pack(pady=20)

# ==========================================================================================
# FUNCTION: show_recon_window()
# Recon tools window (e.g., JDK for Burp)
# ==========================================================================================
def show_recon_window(parent):
    win = Toplevel(parent)
    win.title("Recon Installers")
    win.geometry("350x180")
    Label(win, text="Recon Tools", font=("Arial", 14, "bold")).pack(pady=10)
    Button(win, text="Install JDK 21+ (Temurin)", width=30, command=open_jdk_download).pack(pady=5)
    Button(win, text="Back", width=30, command=win.destroy).pack(pady=20)

# ==========================================================================================
# FUNCTION: show_vulnscan_window()
# Vulnerability scanner tools
# ==========================================================================================
def show_vulnscan_window(parent):
    win = Toplevel(parent)
    win.title("Vulnscan Installers")
    win.geometry("350x200")
    Label(win, text="Vulnscan Tools", font=("Arial", 14, "bold")).pack(pady=10)
    Button(win, text="Install OWASP ZAP", width=30, command=open_zap_installer).pack(pady=5)
    Button(win, text="Back", width=30, command=win.destroy).pack(pady=20)

# ==========================================================================================
# FUNCTION: show_exploitation_window()
# Exploitation tool window — includes Metasploit button
# ==========================================================================================
def show_exploitation_window(parent):
    win = Toplevel(parent)
    win.title("Exploitation Tools")
    win.geometry("350x200")
    Label(win, text="Exploitation Tools", font=("Arial", 14, "bold")).pack(pady=10)
    
    # Launch Metasploit Plugin from CHARLOTTE
    Button(win, text="Launch Metasploit Plugin", width=30, command=launch_metasploit_plugin).pack(pady=5)
    
    Button(win, text="Back", width=30, command=win.destroy).pack(pady=20)

# ==========================================================================================
# FUNCTION: main()
# Main CHARLOTTE Installer GUI loop
# ==========================================================================================
def main():
    root = Tk()
    root.title("C-H-A-R-L-O-T-T-E Installer")
    root.geometry("400x320")

    Label(root, text="C-H-A-R-L-O-T-T-E GUI Installer", font=("Arial", 16, "bold")).pack(pady=10)
    Label(root, text="Select a category:").pack(pady=5)

    Button(root, text="Reverse Engineering (re)", width=30, command=lambda: show_re_window(root)).pack(pady=5)
    Button(root, text="Recon", width=30, command=lambda: show_recon_window(root)).pack(pady=5)
    Button(root, text="Vulnscan", width=30, command=lambda: show_vulnscan_window(root)).pack(pady=5)
    Button(root, text="Exploitation", width=30, command=lambda: show_exploitation_window(root)).pack(pady=5)
    Button(root, text="About", width=30, command=show_about).pack(pady=20)
    Button(root, text="Exit", width=30, command=root.quit).pack(pady=5)

    root.mainloop()

# ==========================================================================================
# ENTRY POINT
# ==========================================================================================
if __name__ == "__main__":
    main()
# ==========================================================================================
# This script provides a GUI installer for C-H-A-R-L-O-T-T-E, allowing users to install various security tools.
# It includes options for reverse engineering, recon, vulnscan, and exploitation tools.