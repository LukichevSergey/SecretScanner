"""py2app entry point — always opens the desktop GUI."""

from secret_scanner.gui import launch_gui

if __name__ == "__main__":
    launch_gui()
