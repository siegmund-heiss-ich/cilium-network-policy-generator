from .templates import *
from .process_labels import *
from .add_rule import add_L3L4_rule

def generate_policy(policies, flow, patternMatches, processedFlows, noIngressEgress, noUsefulLabels, droppedFlows, reservedFlows, L7):
    policy_info = flow.get("flow", {})
    l4_protocol = "TCP" if "TCP" in policy_info.get("l4", {}) else "UDP"
    src_port = policy_info.get("l4", {}).get(l4_protocol, {}).get("source_port", 0)
    dst_port = policy_info.get("l4", {}).get(l4_protocol, {}).get("destination_port", 0)
    direction = policy_info.get('traffic_direction', '')
    src_namespace = process_namespace(policy_info.get("source", {}).get("labels", []))
    dst_namespace = process_namespace(policy_info.get("destination", {}).get("labels", []))
    trace_observation_point = policy_info.get("trace_observation_point", "")
    src_labels = policy_info.get("source", {}).get("labels", [])
    dst_labels = policy_info.get("destination", {}).get("labels", [])

    if policy_info.get("verdict", "").upper() == "DROPPED":
        droppedFlows[0] += 1
        return

    combined_labels = src_labels + dst_labels
    if any("reserved:" in label.lower() for label in combined_labels) and not any("reserved:world" in label.lower() for label in combined_labels) or all(any("reserved:" in label.lower() for label in labels) for labels in [src_labels, dst_labels]):
        reservedFlows[0] += 1
        return

    if policy_info.get('Type') != "L7":
        process_L3L4(policies, direction, trace_observation_point, src_labels, src_namespace, src_port, dst_labels, dst_namespace, dst_port, policy_info, noIngressEgress, noUsefulLabels, patternMatches, processedFlows, l4_protocol)
    else:
        if L7:
            process_L7()

def process_L3L4(policies, direction, trace_observation_point, src_labels, src_namespace, src_port, dst_labels, dst_namespace, dst_port, policy_info, noIngressEgress, noUsefulLabels, patternMatches, processedFlows, l4_protocol):
    match_labels = []
    is_world = False
    if direction == "INGRESS":
        is_ingress = True
        if trace_observation_point == "TO_ENDPOINT" or trace_observation_point == "TO_PROXY" or trace_observation_point == "":
            affected_namespace = dst_namespace
            affected_labels = process_labels_namespace(policy_info, "destination")
            relevant_port = dst_port
            if "reserved:world" in src_labels:
                is_world = True
            else:
                if src_namespace == dst_namespace:
                    match_labels = process_labels_namespace(policy_info, "source")
                else:
                    match_labels = process_labels_cluster(policy_info, "source")
        elif trace_observation_point == "TO_OVERLAY":
            if "reserved:world" in src_labels:
                is_world = True
                affected_namespace = src_namespace
                affected_labels = process_labels_namespace(policy_info, "destination")
                relevant_port = dst_port
            else:
                affected_namespace = src_namespace
                affected_labels = process_labels_namespace(policy_info, "source")
                relevant_port = src_port
                if src_namespace == dst_namespace:
                    match_labels = process_labels_namespace(policy_info, "destination")
                else:
                    match_labels = process_labels_cluster(policy_info, "destination")
        else:
            logging.warning(f"trace_observation_point not handled for flow: {policy_info}")
            return
    elif direction == "EGRESS":
        is_ingress = False
        if trace_observation_point == "TO_ENDPOINT":
            affected_namespace = dst_namespace
            affected_labels = process_labels_namespace(policy_info, "destination")
            relevant_port = src_port
            if "reserved:world" in src_labels:
                is_world = True
            else:
                if src_namespace == dst_namespace:
                    match_labels = process_labels_namespace(policy_info, "source")
                else:
                    match_labels = process_labels_cluster(policy_info, "source")
        elif trace_observation_point == "TO_OVERLAY" or trace_observation_point == "TO_PROXY" or trace_observation_point == "":
            affected_namespace = src_namespace
            affected_labels = process_labels_namespace(policy_info, "source")
            relevant_port = dst_port
            if "reserved:world" in dst_labels:
                is_world = True
            else:
                if src_namespace == dst_namespace:
                    match_labels = process_labels_namespace(policy_info, "destination")
                else:
                    match_labels = process_labels_cluster(policy_info, "destination")
        elif trace_observation_point == "TO_STACK":
            is_world = True
            affected_namespace = src_namespace
            affected_labels = process_labels_namespace(policy_info, "source")
            relevant_port = dst_port
        else:
            logging.warning(f"trace_observation_point not handled for flow: {policy_info}")
            return
    else:
        noIngressEgress[0] += 1
        return

    pattern = create_Pattern(is_world, affected_labels, match_labels, relevant_port, is_ingress)
    if pattern is None:
        noUsefulLabels[0] += 1
        return
    
    process_Result(policies, pattern, patternMatches, processedFlows, affected_labels, relevant_port, l4_protocol, affected_namespace, is_ingress, is_world, match_labels)

def process_L7():
    return

def process_Result(policies, pattern, patternMatches, processedFlows, affected_labels, relevant_port, l4_protocol, affected_namespace, is_ingress, is_world, match_labels):
    if pattern in patternMatches:
        patternMatches[pattern] += 1
        processedFlows[0] += 1
    else:
        patternMatches[pattern] = 1
        policy_id = '-'.join(f"{key}-{value}" for key, value in sorted(affected_labels.items()))
        if policy_id not in policies:
            policies[policy_id] = create_policy_template(policy_id, affected_namespace, affected_labels)
        new_rule = create_rule_template(relevant_port, l4_protocol, match_labels, is_ingress, is_world)
        add_L3L4_rule(policies, policy_id, new_rule, is_ingress, is_world)
        processedFlows[0] += 1
    return

def create_Pattern(is_world, affected_labels, match_labels, relevant_port, is_ingress):
    if is_world:
        if not affected_labels and not match_labels:
            return
        return f"{affected_labels}-reserved:world-{relevant_port}-{is_ingress}"
    else:
        if not affected_labels or not match_labels:
            return
        return f"{affected_labels}-{match_labels}-{relevant_port}-{is_ingress}"