"""py2app build script — produces dist/SecretScanner.app.

Usage:
    .build-venv/bin/python setup.py py2app
"""

from setuptools import setup

APP = ["macapp/launch.py"]
OPTIONS = {
    "argv_emulation": False,
    "packages": ["secret_scanner"],
    "iconfile": None,
    "plist": {
        "CFBundleName": "SecretScanner",
        "CFBundleDisplayName": "SecretScanner",
        "CFBundleIdentifier": "dev.lukichevsergey.secretscanner",
        "CFBundleVersion": "1.0.0",
        "CFBundleShortVersionString": "1.0.0",
        "NSHumanReadableCopyright": "Copyright © 2026 Sergey Lukichev",
        "NSHighResolutionCapable": True,
        "LSMinimumSystemVersion": "11.0",
    },
}

setup(
    app=APP,
    name="SecretScanner",
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
)
