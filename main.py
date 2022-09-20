import argparse
import json
import pickle
import os
import re
import sys
from typing import List
from datetime import datetime
from pathlib import Path

# Apache Tika Python Client Library (Downloads Tika Server in Code) - https://github.com/chrismattmann/tika-python
os.environ['PYTHONIOENCODING'] = 'utf8'
from tika import parser

from concurrent.futures import as_completed, ThreadPoolExecutor
regex_flags = re.MULTILINE | re.DOTALL
# Regex String Sourced from https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/predefined_recognizers/us_ssn_recognizer.py
social_security_regex = re.compile(r"\b([0-9]{3})[- .]([0-9]{2})[- .]([0-9]{4})\b", regex_flags)
# Regex String Sourced from https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/predefined_recognizers/credit_card_recognizer.py
weak_credit_card_regex = re.compile(r"\b((4\d{3})|(5[0-5]\d{2})|(6\d{3})|(1\d{3})|(3\d{3}))[- ]?(\d{3,4})[- ]?(\d{3,4})[- ]?(\d{3,5})\b", regex_flags)

def luhn_checksum(sanitized_value: str) -> bool:
    '''Luhn Checksum checker sourced from https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/predefined_recognizers/credit_card_recognizer.py'''
    def digits_of(n: str) -> List[int]:
        return [int(dig) for dig in str(n)]
    digits = digits_of(sanitized_value)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(str(d * 2)))
    return checksum % 10 == 0

def scan_directory_for_files(scan_dir):
    '''Scans through entire directory tree for files'''
    return_files_list = []
    for root, subdirectories, files_list in os.walk(scan_dir):
        if files_list:
            if not return_files_list:
                return_files_list = [root + '/' + file for file in files_list]
            else:
                return_files_list.extend([root + '/' + file for file in files_list])
    return return_files_list

def content_scan(file_path):
    '''Uses Apache Tika to scan contents of the file'''
    parse_status = "Y"
    parsed_content = ""
    try:
        parse_result = parser.from_file(file_path)
        # https://cwiki.apache.org/confluence/display/TIKA/TikaServer#TikaServer-TikaServerServices
        if parse_result.get('status') != 200:
            if parse_result.get('status') == 204: # Parsed but no content found
                parse_status = "N"
            else: # All other statuses imply inability to parse
                parse_status = "NA"
        parsed_content = parse_result.get('content')
        if not parsed_content:
            parse_status = "N"
    except Exception as e:
        parse_status = "NA"
    return parse_status, parsed_content

def main_file_scan_interface(scan_dir):
    file_paths = scan_directory_for_files(scan_dir)
    file_paths_dict = {file_path: {'scanned': "", 'credit_card_found': False, 'social_security_found': False} for file_path in file_paths}
    flagged_files_report_dict = {}
    if file_paths_dict:
        with ThreadPoolExecutor() as executor:
            file_scan_jobs = {executor.submit(content_scan, file_path): file_path for file_path, _ in file_paths_dict.items()}
            finished_file_scan_paths = []
            for file_scan_job_future in as_completed(file_scan_jobs, 180):
                flag_file = False
                file_path = file_scan_jobs[file_scan_job_future]
                try:
                    content_scan_status, file_content = file_scan_job_future.result()
                except Exception as e:
                    content_scan_status, file_content = "NA", ""
                #finished_file_scan_paths.append(file_scan_jobs[file_scan_job_future])
                file_info = file_paths_dict[file_path]
                file_info['scanned'] = content_scan_status
                if content_scan_status == "Y":
                    if social_security_regex.search(file_content):
                        file_info['social_security_found'] = True
                        flag_file = True
                    if weak_credit_card_match_obj := weak_credit_card_regex.search(file_content):
                        possible_cc_number = weak_credit_card_match_obj[0]
                        if "-" in possible_cc_number:
                            possible_cc_number = possible_cc_number.replace("-", "")
                        if " " in possible_cc_number:
                            possible_cc_number = possible_cc_number.replace(" ", "")
                        if luhn_checksum(possible_cc_number):
                            file_info['credit_card_found'] = True
                            flag_file = True
                if flag_file:
                    flagged_files_report_dict[file_path] = {
                        'credit_card_found': "Yes" if file_info['credit_card_found'] else "No",
                        'social_security_found': "Yes" if file_info['social_security_found'] else "No"
                    }
    return flagged_files_report_dict


if __name__ == '__main__':
    cmd_line_msg = 'Please input a file directory to scan files for any text containing PII (Social Security and Credit Card Numbers)'
    args_parser = argparse.ArgumentParser(prog='piifilescan', description=cmd_line_msg)
    args_parser.add_argument('scan_directory', type=str, default=None, help='Directory containing files or folders')
    args_parser.add_argument('-o', dest='output_directory', type=str, required=False, default=os.getcwd(), help='Where to output the report file. Report file is output to the current directory scanner is run from by default')
    config = args_parser.parse_args()
    if not config.scan_directory or not os.path.isdir(config.scan_directory):
        sys.exit(f'Invalid scan directory: {config.scan_directory}')
    if config.output_directory and not os.path.isdir(config.output_directory):
        sys.exit(f'Output directory is invalid, please set a proper output directory path!: {config.output_directory}')
    print(f"Scanning Directory: {config.scan_directory}")
    flagged_files_report_json = main_file_scan_interface(Path(config.scan_directory))
    time_finished = datetime.now()
    print(f"Finished scan of {config.scan_directory} at {time_finished.isoformat()}!")
    if flagged_files_report_json:
        output_file_report = Path(config.output_directory) / f"pii_files_found_report_{str(time_finished.strftime('%m_%y_%d__%H_%M_%S'))}.json"
        print(f"Found PII in files. Outputting Report in JSON format to: {output_file_report}")
        with output_file_report.open('w') as f:
            json.dump(flagged_files_report_json, f, indent=4)
    else:
        print("Found no PII in any files!")
