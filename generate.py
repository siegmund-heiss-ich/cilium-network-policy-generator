import logging
import json
import sys

from src.generate_policy import *
from src.write_policy import *

def main(argv):
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    try:
        file_path = argv[0]
    except IndexError:
        logging.error('Usage: generate.py <file_path>')
        sys.exit(2)

    policies = {}
    labelPortCounter = {}
    processedFlows = [0]
    noDirection = [0]
    noUsefulLabels = [0]
    totalFlows = 0
    droppedFlows = 0
    reservedFlows = 0
    processingErrors = 0

    with open(file_path, 'r') as file:
        for line in file:
            try:
                log_entry = json.loads(line)
                totalFlows += 1
                # Jump to next iteration if verdict is DROPPED
                if log_entry.get("flow", {}).get("verdict", "").upper() == "DROPPED":
                    droppedFlows += 1
                    continue
                # Jump to next iteration if "reserved:" is in labels
                labels = log_entry.get("flow", {}).get("source", {}).get("labels", []) + log_entry.get("flow", {}).get("destination", {}).get("labels", [])
                if any("reserved:" in label.lower() for label in labels): 
                    reservedFlows += 1
                    continue
                generate_policy(policies, log_entry, labelPortCounter, processedFlows, noDirection, noUsefulLabels)
            except ValueError as e:
                processingErrors += 1
                logging.error(f"Error processing Flow: {e}")
                continue

    processedFlows[0] -= processingErrors
    lostFlows = totalFlows - (processingErrors + droppedFlows + reservedFlows + noUsefulLabels[0] + noDirection[0] + processedFlows[0])
    logging.info(f'Dropped flows: {droppedFlows}')
    logging.info(f'Flow with content "reserved:": {reservedFlows}')
    logging.info(f'Labels not useful: {noUsefulLabels[0]}')
    logging.info(f'Flows with no direction: {noDirection[0]}')
    logging.info(f'Lost flows: {lostFlows}')
    logging.info(f'Processing errors: {processingErrors}')
    logging.info(f'Total flows in file: {totalFlows}')
    logging.info(f'Successfully processed flows: {processedFlows[0]}')
    write_policies_to_files(policies)

if __name__ == '__main__':
    main(sys.argv[1:])