import logging

from .templates import create_rule_template
from .templates import create_policy_template
from .process_labels import process_labels_namespace
from .process_labels import process_labels_cluster

def generate_policy(policies, flow, patternMatches, processedFlows, noIngressEgress, noUsefulLabels):
    policy_info = flow.get("flow", {})
    l4_protocol = "TCP" if "TCP" in policy_info.get("l4", {}) else "UDP"
    src_port = policy_info.get("l4", {}).get(l4_protocol, {}).get("source_port", 0)
    dst_port = policy_info.get("l4", {}).get(l4_protocol, {}).get("destination_port", 0)
    direction = policy_info.get('traffic_direction', '')
    src_namespace = policy_info.get("source", {}).get("namespace", "")
    dst_namespace = policy_info.get("destination", {}).get("namespace", "")
    trace_observation_point = policy_info.get("trace_observation_point", "")
    src_labels = policy_info.get("source", {}).get("labels", [])
    dst_labels = policy_info.get("destination", {}).get("labels", [])

    if any("reserved:world" in label.lower() for label in src_labels):
        return
        is_world = True
        match_labels = None
        if direction == "INGRESS":
            is_ingress = True
        elif direction == "EGRESS":
            is_ingress = False
            affected_namespace = dst_namespace
            affected_labels = process_labels_namespace(policy_info, "destination")
            relevant_port = src_port
    elif any("reserved:world" in label.lower() for label in dst_labels):
        return
        is_world = True
        match_labels = None
        if direction == "INGRESS":
            is_ingress = True
        elif direction == "EGRESS":
            is_ingress = False
            affected_namespace = src_namespace
            affected_labels = process_labels_namespace(policy_info, "source")
            relevant_port = dst_labels

    is_world = False
    if direction == "INGRESS":
        is_ingress = True
        if trace_observation_point == "TO_ENDPOINT":
            affected_namespace = dst_namespace
            affected_labels = process_labels_namespace(policy_info, "destination")
            relevant_port = dst_port
            if src_namespace == dst_namespace:
                match_labels = process_labels_namespace(policy_info, "source")
            else:
                match_labels = process_labels_cluster(policy_info, "source")
        elif trace_observation_point == "TO_OVERLAY":
            affected_namespace = src_namespace
            affected_labels = process_labels_namespace(policy_info, "source")
            relevant_port = src_port
            if src_namespace == dst_namespace:
                match_labels = process_labels_namespace(policy_info, "destination")
            else:
                match_labels = process_labels_cluster(policy_info, "destination")
    elif direction == "EGRESS":
        is_ingress = False
        if trace_observation_point == "TO_ENDPOINT":
            affected_namespace = dst_namespace
            affected_labels = process_labels_namespace(policy_info, "destination")
            relevant_port = src_port
            if src_namespace == dst_namespace:
                match_labels = process_labels_namespace(policy_info, "source")
            else:
                match_labels = process_labels_cluster(policy_info, "source")
        elif trace_observation_point == "TO_OVERLAY":
            affected_namespace = src_namespace
            affected_labels = process_labels_namespace(policy_info, "source")
            relevant_port = dst_port
            if src_namespace == dst_namespace:
                match_labels = process_labels_namespace(policy_info, "destination")
            else:
                match_labels = process_labels_cluster(policy_info, "destination")
    else:
        noIngressEgress[0] += 1
        return policies, noIngressEgress
    
    if not affected_labels or not match_labels:
        noUsefulLabels[0] += 1
        return policies, noUsefulLabels
    
    if not is_world:
        pattern = f"{affected_labels}-{match_labels}-{relevant_port}-{is_ingress}"
    else:
        pattern = f"reserved:world-{relevant_port}-{is_ingress}"
    
    if pattern in patternMatches:
        patternMatches[pattern] += 1
        processedFlows[0] += 1
    else:
        patternMatches[pattern] = 1
        policy_id = '-'.join(f"{key}-{value}" for key, value in sorted(affected_labels.items()))
        if policy_id not in policies:
            policies[policy_id] = create_policy_template(policy_id, affected_namespace, affected_labels)
        new_rule = create_rule_template(relevant_port, l4_protocol, match_labels, is_ingress)
        update_or_add_rule(policies, policy_id, new_rule, is_ingress)
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