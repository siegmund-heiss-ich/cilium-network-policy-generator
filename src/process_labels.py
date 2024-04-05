import re
import logging

def process_labels_namespace(policy_info, label_type):
    labels_dict = {}
    for label in policy_info.get(label_type, {}).get("labels", []):
        try:
            key, value = label.split("=")
            key = key.split(":")[-1]
            if not is_key_of_no_interest(key):
                labels_dict[key] = value
        except ValueError:
            logging.warning(f"Could not parse label: {label}")
    return labels_dict

def process_labels_cluster(policy_info, label_type):
    labels_dict = {}
    for label in policy_info.get(label_type, {}).get("labels", []):
        try:
            key, value = label.split("=")
            labels_dict[key] = value
        except ValueError:
            logging.warning(f"Could not parse label: {label}")
    return labels_dict

def is_key_of_no_interest(key):
    patterns_of_no_interest = [".*cilium.*", ".*kubernetes.*", ".*k8s-app.*", "component"]
    return any(re.match(pattern, key) for pattern in patterns_of_no_interest)