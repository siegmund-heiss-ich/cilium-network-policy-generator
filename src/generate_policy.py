from .templates import create_rule_template
from .templates import create_policy_template
from .process_labels import process_labels_namespace
from .process_labels import process_labels_cluster
from .add_rule import add_L3L4_rule

def generate_policy(policies, flow, patternMatches, processedFlows, noIngressEgress, noUsefulLabels, droppedFlows, reservedFlows):
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
    match_labels = []
    is_world = False

    if policy_info.get("verdict", "").upper() == "DROPPED":
        droppedFlows[0] += 1
        return

    if any("reserved:" in label.lower() for label in src_labels + dst_labels):
        has_reserved_world_src = any("reserved:world" in label.lower() for label in src_labels)
        has_reserved_world_dst = any("reserved:world" in label.lower() for label in dst_labels)
        if not (has_reserved_world_src and not has_reserved_world_dst):
            reservedFlows[0] += 1
            return

    if direction == "INGRESS":
        is_ingress = True
        if trace_observation_point == "TO_ENDPOINT":
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
            print(policy_info)
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
        elif trace_observation_point == "TO_OVERLAY":
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
            return
    else:
        noIngressEgress[0] += 1
        return
    
    if is_world:
        if not affected_labels and not match_labels:
            noUsefulLabels[0] += 1
            return
        pattern = f"{affected_labels}-reserved:world-{relevant_port}-{is_ingress}"
    else:
        if not affected_labels or not match_labels:
            noUsefulLabels[0] += 1
            return
        pattern = f"{affected_labels}-{match_labels}-{relevant_port}-{is_ingress}"

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