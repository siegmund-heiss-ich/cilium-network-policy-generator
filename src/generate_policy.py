import logging

from .templates import create_rule_template
from .templates import create_policy_template

def generate_policy(policies, policy_info, processedFlows, noIngressEgress, specPortRange):

    destination_port = policy_info.get('destination_port', 0)
    protocol = policy_info.get('l4_protocol', '')

    try:
        destination_labels = {k: v for k, v in (label.split('=') for label in policy_info.get('destination_labels', []))}
        source_labels = {k: v for k, v in (label.split('=') for label in policy_info.get('source_labels', []))}
    except ValueError as e:
        logging.error(f"Parsing error: {e}")
        return policies 

    if policy_info.get('traffic_direction', '') == "INGRESS":
        is_ingress = True
        affected_labels = destination_labels
        relevant_port = destination_port
        match_Labels = source_labels
    elif policy_info.get('traffic_direction', '') == "EGRESS":
        is_ingress = False
        affected_labels = source_labels
        relevant_port = ''
        match_Labels = destination_labels
    else:
        noIngressEgress[0] += 1
        return policies, noIngressEgress

    if is_ingress and relevant_port < 10000 or not is_ingress:
        policy_id = '-'.join(f"{key}-{value}" for key, value in sorted(affected_labels.items()))
        if policy_id not in policies:
            policies[policy_id] = create_policy_template(policy_id, affected_labels)
        new_rule = create_rule_template(relevant_port, protocol, match_Labels, is_ingress)
        update_or_add_rule(policies, policy_id, new_rule, is_ingress)
        processedFlows[0] += 1
    else:
        specPortRange[0] += 1
    return policies, processedFlows, specPortRange

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
