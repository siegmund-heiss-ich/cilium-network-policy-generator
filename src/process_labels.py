import re
import logging

def process_labels_namespace(policy_info, label_type):
    labels_dict = {}
    for label in policy_info.get(label_type, {}).get("labels", []):
        try:
            key, value = label.split("=")
            key = key.split(":")[-1]  # Only take the last part after the last colon
            if not is_key_of_no_interest(key, "namespace"):
                labels_dict[key] = value
        except ValueError:
            logging.warning(f"Could not parse label: {label}")
    return labels_dict

def process_labels_cluster(policy_info, label_type):
    labels_dict = {}
    for label in policy_info.get(label_type, {}).get("labels", []):
        try:
            key, value = label.split("=")
            if not is_key_of_no_interest(key, "cluster"):
                labels_dict[key] = value
        except ValueError:
            logging.warning(f"Could not parse label: {label}")
    return labels_dict

def is_key_of_no_interest(key, context):
    patterns_of_no_interest = {
        "namespace": [".*cilium.*", ".*kubernetes.*", ".*k8s-app.*"],
        "cluster": [".*policy.*"]
    }
    patterns = patterns_of_no_interest.get(context, [])
    return any(re.match(pattern, key) for pattern in patterns)
