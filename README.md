# SAGE ufsfile

Python module and CLI utility for the UFS files use by the SAGE engine.


## Overview

Useful for the UFS files in some SAGE (Sapphire Advanced Game Engine) games.

Works with both Python 2 and Python 3.

Also included is a 010 Editor Binary Template for this file format.

Games known to use this format:

- [Barbarian (2002)](https://en.wikipedia.org/wiki/Barbarian_%282002_video_game%29): PS2, Xbox

NOTE: Creating new archives is not currently supported. Feel free to fork the repo and add this feature.


## Usage

```
usage: ufsfile.py [-h] [-l] paths [paths ...]

positional arguments:
  paths       Paths to run on

optional arguments:
  -h, --help  show this help message and exit
  -l, --list  Just list the files
```


## Bugs

If you find a bug or have compatibility issues, please open a ticket under issues section for this repository.


## License

Copyright (c) 2018 JrMasterModelBuilder

Licensed under the Mozilla Public License, v. 2.0

RNC ProPack unpacker code based on a class in [ScummVM](https://github.com/scummvm/scummvm)
