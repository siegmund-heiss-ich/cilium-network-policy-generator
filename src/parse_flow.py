import json
import logging

def parse_flow(log_entry):
    try:
        # Extract necessary information for CNP
        flow_info = log_entry.get("flow", {})
        src_labels = [label.split(':')[1] for label in flow_info.get("source", {}).get("labels", []) if "kubernetes" not in label and "cilium" not in label and "k8s-app" not in label]
        dst_labels = [label.split(':')[1] for label in flow_info.get("destination", {}).get("labels", []) if "kubernetes" not in label and "cilium" not in label and "k8s-app" not in label]
        # src_namespace = flow_info.get("source", {}).get("namespace", "")
        # dst_namespace = flow_info.get("destination", {}).get("namespace", "")
        # src_pod_name = flow_info.get("source", {}).get("pod_name", "")
        # dst_pod_name = flow_info.get("destination", {}).get("pod_name", "")

        # IP addresses and L4 details
        # src_ip = flow_info.get("IP", {}).get("source", "")
        # dst_ip = flow_info.get("IP", {}).get("destination", "")
        traffic_direction = flow_info.get("traffic_direction", "")

        # Assuming L4 protocol details based on the presence of specific keys
        l4_protocol = "TCP" if "TCP" in flow_info.get("l4", {}) else "UDP"
        src_port = flow_info.get("l4", {}).get(l4_protocol, {}).get("source_port", 0)
        dst_port = flow_info.get("l4", {}).get(l4_protocol, {}).get("destination_port", 0)
        # flags = flow_info.get("l4", {}).get("TCP", {}).get("flags", {})

        flow_entries = {
            "source_labels": src_labels,
            "destination_labels": dst_labels,
            # "source_namespace": src_namespace,
            # "destination_namespace": dst_namespace,
            # "source_pod_name": src_pod_name,
            # "destination_pod_name": dst_pod_name,
            # "source_ip": src_ip,
            # "destination_ip": dst_ip,
            # "flags": flags,
            "traffic_direction": traffic_direction,
            "l4_protocol": l4_protocol,
            "source_port": src_port,
            "destination_port": dst_port,
        }
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing Hubble Flow: {e}")

    return flow_entries
