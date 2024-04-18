import logging
import json
import sys
import argparse
import time

from src.generate_policy import *
from src.write_policy import *

def update_progress(processed, start_time, total_lines):
    if total_lines > 0:
        percent = (processed / total_lines) * 100
        bar_length = 40
        filled_length = int(round(bar_length * percent / 100))
        bar = '#' * filled_length + '-' * (bar_length - filled_length)
        sys.stdout.write(f"\rProcessed {processed} entries |{bar}| {percent:.2f}% complete")
        sys.stdout.flush()

def main(argv):
    parser = argparse.ArgumentParser(description='Process flags.')
    parser.add_argument('file_path', type=str, help='The path to the file to be processed')
    l7_group = parser.add_mutually_exclusive_group()
    l7_group.add_argument('-L7allowAll', action='store_true', help='Writes policies allowing all L7 communication.')
    l7_group.add_argument('-L7', action='store_true', help='Write policies including L7 rules.')
    args = parser.parse_args(argv)

    file_path = args.file_path

    logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

    file_path = args.file_path

    policies = {}
    patternMatches = {}
    processedFlows = [0]
    noDirection = [0]
    noUsefulLabels = [0]
    droppedFlows = [0]
    reservedFlows = [0]
    totalFlows = 0
    processingErrors = 0

    start_time = time.time()
    last_update_time = start_time

    with open(file_path, 'r') as file:
        logging.info("Counting lines")
        totalFlows = sum(1 for _ in file)
        file.seek(0)
        for i, line in enumerate(file):
            try:
                log_entry = json.loads(line)
                generate_policy(policies, log_entry, patternMatches, processedFlows, noDirection, noUsefulLabels, droppedFlows, reservedFlows, args.L7)
            except ValueError as e:
                processingErrors += 1
                logging.debug(f"Processing error: {e}, Flow: {line.strip()}")
                continue

            current_time = time.time()
            if current_time - last_update_time >= 1:
                update_progress(i, start_time, totalFlows)
                last_update_time = current_time

    update_progress(i, start_time, totalFlows)
    sys.stdout.write('\n')

    write_policies_to_files(policies, patternMatches, args.L7allowAll)

    logging.info(f'Dropped flows: {droppedFlows[0]}')
    logging.info(f'Flow with unuseful content "reserved:*": {reservedFlows[0]}')
    logging.info(f'Labels not useful: {noUsefulLabels[0]}')
    logging.info(f'Flows with no direction: {noDirection[0]}')
    logging.info(f'Processing errors: {processingErrors}')
    logging.info(f'Lost flows: {totalFlows - sum([processingErrors, droppedFlows[0], reservedFlows[0], noUsefulLabels[0], noDirection[0], processedFlows[0]])}')
    logging.info(f'Total flows in file: {totalFlows}')
    logging.info(f'Successfully processed flows: {processedFlows[0]}')

if __name__ == '__main__':
    main(sys.argv[1:])