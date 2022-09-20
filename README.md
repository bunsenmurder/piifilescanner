# PII File Scanner
Python script that uses Apache Tika to scan files in a directory for any Credit Card Numbers or Social Security Numbers!

## Requirements
* Java >= 7 
* Python >= 3.8
* tika = 1.24

## Installation
Run command below to install tika:
```
pip3 install tika
```

## Running
Command to scan a drive or directory (e.g. 'python3 main.py ~/piifiles/' )
```
python3 main.py [DIRECTORY_PATH]
```

Command to view help manual
```
python3 main.py -h
```

## Sources
* https://tika.apache.org/
* https://github.com/chrismattmann/tika-python
* https://cwiki.apache.org/confluence/display/TIKA/TikaServer
* https://github.com/microsoft/presidio/blob/main/presidio-analyzer/
