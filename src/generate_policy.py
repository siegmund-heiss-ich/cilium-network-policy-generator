from .templates import *
from .process_labels import *
from .add_rule import add_L3L4_rule, add_L7_rule
from urllib.parse import urlparse

def generate_policy(policies, flow, patternMatches, processedFlows, noIngressEgress, noUsefulLabels, droppedFlows, reservedFlows, L7):
    policy_info = flow.get("flow", {})
    l4_protocol = "TCP" if "TCP" in policy_info.get("l4", {}) else "UDP"
    src_port = policy_info.get("l4", {}).get(l4_protocol, {}).get("source_port", 0)
    dst_port = policy_info.get("l4", {}).get(l4_protocol, {}).get("destination_port", 0)
    direction = policy_info.get('traffic_direction', '')
    src_namespace = process_namespace(policy_info.get("source", {}).get("labels", []))
    dst_namespace = process_namespace(policy_info.get("destination", {}).get("labels", []))
    src_labels = policy_info.get("source", {}).get("labels", [])
    dst_labels = policy_info.get("destination", {}).get("labels", [])
    match_labels = []
    is_world = False

    if policy_info.get("verdict", "").upper() == "DROPPED":
        droppedFlows[0] += 1
        return

    combined_labels = src_labels + dst_labels
    if any("reserved:" in label.lower() for label in combined_labels) and not any("reserved:world" in label.lower() for label in combined_labels) or all(any("reserved:" in label.lower() for label in labels) for labels in [src_labels, dst_labels]):
        reservedFlows[0] += 1
        return

    is_reply = policy_info.get("is_reply")
    if direction == "INGRESS":
        is_ingress = True
        affected_namespace = src_namespace if is_reply else dst_namespace
        affected_labels = process_labels_namespace(policy_info, "source" if is_reply else "destination")
        relevant_port = src_port if is_reply else dst_port
        labels_to_check = dst_labels if is_reply else src_labels

        if "reserved:world" in labels_to_check:
            is_world = True
        else:
            if src_namespace == dst_namespace:
                match_labels = process_labels_namespace(policy_info, "destination" if is_reply else "source")
            else:
                match_labels = process_labels_cluster(policy_info, "destination" if is_reply else "source")

    elif direction == "EGRESS":
        is_ingress = False
        affected_namespace = dst_namespace if is_reply else src_namespace
        affected_labels = process_labels_namespace(policy_info, "destination" if is_reply else "source")
        relevant_port = src_port if is_reply else dst_port
        labels_to_check = src_labels if is_reply else dst_labels

        if "reserved:world" in labels_to_check:
            is_world = True
        else:
            if src_namespace == dst_namespace:
                match_labels = process_labels_namespace(policy_info, "source" if is_reply else "destination")
            else:
                match_labels = process_labels_cluster(policy_info, "source" if is_reply else "destination")
    else:
        noIngressEgress[0] += 1
        return

    pattern = create_pattern(is_world, affected_labels, match_labels, relevant_port, is_ingress)
    if not pattern:
        noUsefulLabels[0] += 1
        return
    
    process_L3L4_result(policies, pattern, patternMatches, processedFlows, affected_labels, relevant_port, l4_protocol, affected_namespace, is_ingress, is_world, match_labels)

    if policy_info.get('Type') == "L7" and L7:
        process_L7_result(policy_info, policies, affected_labels, relevant_port, is_ingress, pattern, patternMatches, is_world)

def process_L3L4_result(policies, pattern, patternMatches, processedFlows, affected_labels, relevant_port, l4_protocol, affected_namespace, is_ingress, is_world, match_labels):
    if pattern in patternMatches:
        patternMatches[pattern] += 1
        processedFlows[0] += 1
    else:
        patternMatches[pattern] = 1
        policy_id = create_policy_id(affected_labels)
        if policy_id not in policies:
            policies[policy_id] = create_policy_template(policy_id, affected_namespace, affected_labels)
        new_rule = create_L3L4_rule_template(relevant_port, l4_protocol, match_labels, is_ingress, is_world)
        add_L3L4_rule(policies, policy_id, new_rule, is_ingress, is_world)
        processedFlows[0] += 1

def process_L7_result(policy_info, policies, affected_labels, relevant_port, is_ingress, pattern, patternMatches, is_world):
    policy_id = create_policy_id(affected_labels)
    L7_info = policy_info.get('l7', {})
    if 'http' in L7_info:
        L7_protocol = 'http'
        http = L7_info.get('http', {})
        parsed_url = urlparse(http.get('url'))
        new_rule = {"method": http.get('method'), "path": parsed_url.path}
        pattern += f"-{new_rule}"
        if pattern in patternMatches:
            patternMatches[pattern] += 1
        else:
            patternMatches[pattern] = 1
            add_L7_rule(policies, policy_id, is_ingress, relevant_port, L7_protocol, new_rule, is_world)
    else:
        logging.warning("L7 flows other than http are not supported yet!")

def create_policy_id(affected_labels):
    return '-'.join(f"{key}-{value}" for key, value in sorted(affected_labels.items()))

def create_pattern(is_world, affected_labels, match_labels, relevant_port, is_ingress):
    if is_world:
        if not (affected_labels or match_labels):
            return
        pattern = f"{affected_labels}-reserved:world-{relevant_port}-{is_ingress}"
    else:
        if not (affected_labels and match_labels):
            return
        pattern = f"{affected_labels}-{match_labels}-{relevant_port}-{is_ingress}"
    return pattern