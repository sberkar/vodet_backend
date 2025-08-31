import pyshark
import pandas as pd
import numpy as np
import collections
import os

def process_pcap_for_model(pcap_file, output_csv, jobid):
    print(f"Processing {pcap_file}...")

    jobfile = os.path.join('jobs', f"{jobid}_job.json")
    os.makedirs('jobs', exist_ok=True)
    status = 'processing'
    open(jobfile, 'w').write(f'{{"job_id": "{jobid}", "status": "{status}", "output": "{output_csv}"}}')

    flows = collections.defaultdict(lambda: {'packets': [], 'timestamps': []})
    
    capture = pyshark.FileCapture(pcap_file, display_filter='udp or tcp')

    packet_count = 0
    try:
        for packet in capture:
            packet_count += 1
            if packet_count % 1000 == 0:
                print(f"Processed {packet_count} packets...")

            try:
                protocol = packet.transport_layer
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                src_port = packet[protocol].srcport
                dst_port = packet[protocol].dstport
                timestamp = float(packet.sniff_timestamp)
                packet_size = int(packet.length)
                
                flow_key = tuple(sorted((src_ip, dst_ip))) + tuple(sorted((src_port, dst_port)))
                
                flows[flow_key]['packets'].append(packet_size)
                flows[flow_key]['timestamps'].append(timestamp)
                flows[flow_key]['protocol'] = protocol
            
            except AttributeError:
                continue
    finally:
        capture.close()
    
    print(f"Finished parsing. Found {len(flows)} unique flows.")

    dataset_rows = []
    for key, flow_data in flows.items():
        if len(flow_data['packets']) < 2:
            continue  # Skip flows with too few packets for analysis

        flow_duration = max(flow_data['timestamps']) - min(flow_data['timestamps'])
        inter_arrival_times = [
            flow_data['timestamps'][i] - flow_data['timestamps'][i-1]
            for i in range(1, len(flow_data['timestamps']))
        ]
        
        # Calculate statistical features
        total_packets = len(flow_data['packets'])
        total_bytes = sum(flow_data['packets'])
        avg_packet_size = np.mean(flow_data['packets'])
        std_packet_size = np.std(flow_data['packets'])
        avg_iat = np.mean(inter_arrival_times)
        jitter = np.std(inter_arrival_times) if len(inter_arrival_times) > 1 else 0


        row = {
            'src_ip': key[0],
            'dst_ip': key[1],
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'avg_packet_size': avg_packet_size,
            'std_packet_size': std_packet_size,
            'avg_iat': avg_iat,
            'jitter': jitter,
            'flow_duration': flow_duration,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port
        }
        dataset_rows.append(row)

    # Step 4: Create and save the DataFrame
    df = pd.DataFrame(dataset_rows)
    print(df.head())
    df.to_csv(output_csv, index=False)
    print(f"Successfully saved dataset to {output_csv}")
    status = 'completed'
    open(jobfile, 'w').write(f'{{"job_id": "{jobid}", "status": {0}, "output": "{jobid}_processed.csv"}}')

    print("\nDataset ready for model predictions!")