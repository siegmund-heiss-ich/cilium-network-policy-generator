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
    source_namespace = policy_info.get("source", {}).get("namespace", "")
    destination_namespace = policy_info.get("destination", {}).get("namespace", "")
    logging.debug(f"{source_namespace} {destination_namespace}")

    if direction is "INGRESS":
        is_ingress = True
        affected_labels = process_labels_namespace(policy_info, "destination")
        relevant_port = destination_port
        if source_namespace == destination_namespace:
            match_Labels = process_labels_namespace(policy_info, "source")
        else:
            match_Labels = process_labels_cluster(policy_info, "source")
    elif direction == "EGRESS":
        is_ingress = False
        affected_labels = process_labels_namespace(policy_info, "source")
        relevant_port = source_port
        if source_namespace == destination_namespace:
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
            policies[policy_id] = create_policy_template(policy_id, affected_labels)
        new_rule = create_rule_template(relevant_port, l4_protocol, match_Labels, is_ingress)
        update_or_add_rule(policies, policy_id, new_rule, is_ingress)
        processedFlows[0] += 1

def update_or_add_rule(policies, policy_id, new_rule, is_ingress):
    rule_key = "ingress" if is_ingress else "egress"
    policy = policies.get(policy_id)

    if not policy:
        logging.error(f"Policy {policy_id} not found.")
        return

    # Ensure the rule_key section exists in the policy
    if rule_key not in policy["spec"]:
        policy["spec"][rule_key] = [new_rule]
        return

    # Define the key based on whether the rule is ingress or egress
    endpoints_key = "fromEndpoints" if is_ingress else "toEndpoints"
    new_labels = new_rule[endpoints_key][0]["matchLabels"]

    # For ingress, handle ports. For egress, assume no ports.
    new_ports = new_rule.get("toPorts", []) if is_ingress else []

    existing_rule_found = False
    for rule in policy["spec"][rule_key]:
        # Match the rule based on labels
        if endpoints_key in rule and rule[endpoints_key][0]["matchLabels"] == new_labels:
            existing_rule_found = True
            # For ingress rules, update or add new ports
            if is_ingress:
                for new_port in new_ports:
                    if new_port not in rule.get("toPorts", []):
                        rule["toPorts"] = rule.get("toPorts", []) + [new_port]
            break

    # If no existing rule matched the new labels, add the new rule
    if not existing_rule_found:
        policy["spec"][rule_key].append(new_rule)