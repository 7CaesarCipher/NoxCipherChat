"""Run pip with a fallback for Python builds missing the macOS version."""
import platform
import re
import runpy
import subprocess


def main():
    if not platform.mac_ver()[0]:
        version = subprocess.check_output(
            ["/usr/bin/sw_vers", "-productVersion"], text=True
        ).strip()
        if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", version):
            raise RuntimeError(f"Cannot determine macOS version: {version!r}")
        original_mac_ver = platform.mac_ver

        def mac_ver():
            release, info, machine = original_mac_ver()
            return release or version, info, machine or platform.machine()

        platform.mac_ver = mac_ver
    runpy.run_module("pip", run_name="__main__")


if __name__ == "__main__":
    main()
