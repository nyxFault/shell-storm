# shell-storm

![License](https://img.shields.io/badge/license-GPLv3-blue.svg)
![Python](https://img.shields.io/badge/python-3.6+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)

A modern Python 3 enhancement of the original Shell-Storm shellcode API. This tool fixes the broken `-display` functionality by implementing robust HTML parsing to extract shellcodes directly from web pages, as the original API endpoints are no longer maintained.

## What's New?

- **Fixed Display Functionality**: The broken `-display` command now works flawlessly
- **Python 3 Native**: Complete compatibility with modern Python versions
- **Smart Web Scraping**: Robust HTML parsing extracts shellcodes directly from web pages
- **Improved Output**: Clean, formatted results with color support

## Installation

```bash
git clone https://github.com/nyxFault/shell-storm.git
cd shell-storm

# Search for shellcodes (use lowercase with * as separator)
python3 shell-storm.py -search linux*x86*bind

# Display specific shellcode by ID
python3 shell-storm.py -display 827

# Show tool version and credits
python3 shell-storm.py -version
```

## Acknowledgments

- **Jonathan Salwan** - Original creator of the Shell-Storm API and maintainer of the invaluable shellcode database
- **Shell-Storm Project** - For providing the comprehensive shellcode repository at [shell-storm.org](https://shell-storm.org/shellcode/index.html)

*This project stands on the shoulders of their pioneering work in the security community.*
