
import sys
import os
import subprocess
import webbrowser
from tkinter import Tk, Label, Button, messagebox, Toplevel

def open_ghidra_installer():
    subprocess.Popen([sys.executable, os.path.join(os.path.dirname(__file__), "ghidra", "ghidra_installer.py")])

def open_binary_ninja_installer():
    subprocess.Popen([sys.executable, os.path.join(os.path.dirname(__file__), "binary_ninja", "binary_ninja_installer.py")])

def open_jdk_download():
    webbrowser.open("https://adoptium.net/temurin/releases")

def show_about():
    messagebox.showinfo("About", "C-H-A-R-L-O-T-T-E GUI Installer\nModular security framework\nhttps://github.com/Core-Creates/C-H-A-R-L-O-T-T-E")

def show_re_window(parent):
    win = Toplevel(parent)
    win.title("Reverse Engineering Installers")
    win.geometry("350x220")
    Label(win, text="Reverse Engineering Tools", font=("Arial", 14, "bold")).pack(pady=10)
    Button(win, text="Install Ghidra (Headless)", width=30, command=open_ghidra_installer).pack(pady=5)
    Button(win, text="Install Binary Ninja (Free)", width=30, command=open_binary_ninja_installer).pack(pady=5)
    Button(win, text="Back", width=30, command=win.destroy).pack(pady=20)

def show_recon_window(parent):
    win = Toplevel(parent)
    win.title("Recon Installers")
    win.geometry("350x180")
    Label(win, text="Recon Tools", font=("Arial", 14, "bold")).pack(pady=10)
    Button(win, text="Install JDK 21+ (Temurin)", width=30, command=open_jdk_download).pack(pady=5)
    # Add more recon tool installers here as needed
    Button(win, text="Back", width=30, command=win.destroy).pack(pady=20)

def show_vulnscan_window(parent):
    win = Toplevel(parent)
    win.title("Vulnscan Installers")
    win.geometry("350x150")
    Label(win, text="Vulnscan Tools", font=("Arial", 14, "bold")).pack(pady=10)
    # Add vulnscan tool installers here as needed
    Button(win, text="Back", width=30, command=win.destroy).pack(pady=20)

def main():
    root = Tk()
    root.title("C-H-A-R-L-O-T-T-E Installer")
    root.geometry("400x320")

    Label(root, text="C-H-A-R-L-O-T-T-E GUI Installer", font=("Arial", 16, "bold")).pack(pady=10)
    Label(root, text="Select a category:").pack(pady=5)

    Button(root, text="Reverse Engineering (re)", width=30, command=lambda: show_re_window(root)).pack(pady=5)
    Button(root, text="Recon", width=30, command=lambda: show_recon_window(root)).pack(pady=5)
    Button(root, text="Vulnscan", width=30, command=lambda: show_vulnscan_window(root)).pack(pady=5)
    Button(root, text="About", width=30, command=show_about).pack(pady=20)
    Button(root, text="Exit", width=30, command=root.quit).pack(pady=5)

    root.mainloop()


if __name__ == "__main__":
    main()
