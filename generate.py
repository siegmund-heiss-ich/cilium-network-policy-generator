import logging
import json
import sys
import argparse

from src.generate_policy import *
from src.write_policy import *

def main(argv):
    parser = argparse.ArgumentParser(description='Process flags.')
    parser.add_argument('file_path', type=str, help='The path to the file to be processed')
    l7_group = parser.add_mutually_exclusive_group()
    l7_group.add_argument('-L7allowAll', action='store_true', help='Writes policies allowing all L7 communication.')
    l7_group.add_argument('-L7', action='store_true', help='Write policies including L7 rules.')
    args = parser.parse_args(argv)

    file_path = args.file_path

    logging.basicConfig()
    logging.getLogger().setLevel(logging.INFO)

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

    with open(file_path, 'r') as file:
        for line in file:
            try:
                log_entry = json.loads(line)
                totalFlows += 1
                generate_policy(policies, log_entry, patternMatches, processedFlows, noDirection, noUsefulLabels, droppedFlows, reservedFlows)
            except ValueError as e:
                processingErrors += 1
                logging.debug(f"Processing error: {e}, Flow: {log_entry}")
                continue

    write_policies_to_files(policies, patternMatches, args.L7allowAll)
    processedFlows[0] -= processingErrors
    lostFlows = totalFlows - (processingErrors + droppedFlows[0] + reservedFlows[0] + noUsefulLabels[0] + noDirection[0] + processedFlows[0])
    logging.info(f'Dropped flows: {droppedFlows[0]}')
    logging.info(f'Flow with unuseful content "reserved:*": {reservedFlows[0]}')
    logging.info(f'Labels not useful: {noUsefulLabels[0]}')
    logging.info(f'Flows with no direction: {noDirection[0]}')
    logging.info(f'Processing errors: {processingErrors}')
    logging.info(f'Lost flows: {lostFlows}')
    logging.info(f'Total flows in file: {totalFlows}')
    logging.info(f'Successfully processed flows: {processedFlows[0]}')

if __name__ == '__main__':
    main(sys.argv[1:])