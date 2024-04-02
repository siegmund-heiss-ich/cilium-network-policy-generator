import logging

from .templates import create_rule_template
from .templates import create_policy_template
from .process_labels import process_labels_namespace
from .process_labels import process_labels_cluster

def generate_policy(policies, flow, labelPortCounter, processedFlows, noIngressEgress, noUsefulLabels):

    policy_info = flow.get("flow", {})
    l4_protocol = "TCP" if "TCP" in policy_info.get("l4", {}) else "UDP"
    source_port = policy_info.get("l4", {}).get(l4_protocol, {}).get("source_port", 0)
    destination_port = policy_info.get("l4", {}).get(l4_protocol, {}).get("destination_port", 0)
    direction = policy_info.get('traffic_direction', '')
    src_namespace = policy_info.get("source", {}).get("namespace", "")
    dst_namespace = policy_info.get("destination", {}).get("namespace", "")
    logging.debug(f"{src_namespace} {dst_namespace}")

    if direction == "INGRESS":
        is_ingress = True
        affected_namespace = dst_namespace
        affected_labels = process_labels_namespace(policy_info, "destination")
        relevant_port = destination_port
        if src_namespace == dst_namespace:
            match_Labels = process_labels_namespace(policy_info, "source")
        else:
            match_Labels = process_labels_cluster(policy_info, "source")
    elif direction == "EGRESS":
        is_ingress = False
        affected_namespace = src_namespace
        affected_labels = process_labels_namespace(policy_info, "source")
        relevant_port = source_port
        if src_namespace == dst_namespace:
            match_Labels = process_labels_namespace(policy_info, "destination")
        else:
            match_Labels = process_labels_cluster(policy_info, "destination")
    else:
        noIngressEgress[0] += 1
        return policies, noIngressEgress
    
    if not affected_labels or not match_Labels:
        noUsefulLabels[0] += 1
        return policies, noUsefulLabels
    
    label_port_key = f"{match_Labels}-{relevant_port}-{is_ingress}"
    labelPortCounter[label_port_key] = labelPortCounter.get(label_port_key, 0)
    labelPortCounter[label_port_key] += 1
    logging.debug(f"{label_port_key} count {labelPortCounter[label_port_key]}")

    if labelPortCounter[label_port_key] > 3:
        policy_id = '-'.join(f"{key}-{value}" for key, value in sorted(affected_labels.items()))
        if policy_id not in policies:
            policies[policy_id] = create_policy_template(policy_id, affected_namespace, affected_labels)
        new_rule = create_rule_template(relevant_port, l4_protocol, match_Labels, is_ingress)
        update_or_add_rule(policies, policy_id, new_rule, is_ingress)
        processedFlows[0] += 1
    else:
        processedFlows[0] += 1

def update_or_add_rule(policies, policy_id, new_rule, is_ingress):
    rule_key = "ingress" if is_ingress else "egress"
    policy = policies.get(policy_id)

    if rule_key not in policy["spec"]:
        policy["spec"][rule_key] = [new_rule]

    endpoints_key = "fromEndpoints" if is_ingress else "toEndpoints"
    new_labels = new_rule[endpoints_key][0]["matchLabels"]

    new_ports = new_rule.get("toPorts", [])

    existing_rule_found = False
    for rule in policy["spec"][rule_key]:
        if endpoints_key in rule and rule[endpoints_key][0]["matchLabels"] == new_labels:
            existing_rule_found = True
            existing_ports = rule.get("toPorts", [])
            for new_port in new_ports:
                if new_port not in existing_ports:
                    rule["toPorts"] = existing_ports + [new_port]
            break

    if not existing_rule_found:
        policy["spec"][rule_key].append(new_rule)