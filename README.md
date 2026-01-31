# 🐞 WhatThePy Deobfuscator

A deobfuscator built for decompiling python files masked with WhatThePy

## 📸 Showcase

<picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/0131.gif">
    <source media="(prefers-color-scheme: light)" srcset="assets/0131.gif">
    <img alt="GIFCLI" src="assets/sample.gif">
</picture>

## Features
- Supports zlib/XOR/base85 chunked payloads
- Detects and reconstructs joined chunk variables
- Handles decoy variables and exec wrappers
- Compatible with Python 3.6+


## Usage
### Just Run It?
simple.


### Command Line
```sh
python deobfuscator.py <input_file> [output_file]
```
- If arguments are provided, the script will use them and print detected values.
- If no arguments are provided, the script will prompt for file paths interactively.

### MSYS Path Support
You can use MSYS/Cygwin-style paths (e.g. `/c/Users/...`) on Windows. These will be automatically converted to Windows format.

### Example
```sh
python deobfuscator.py /c/Users/rep/Desktop/WTP/simple_obfuscated.py output.py
```

## License
MIT

## Credits
Developed by soberized
https://github.com/soberized
