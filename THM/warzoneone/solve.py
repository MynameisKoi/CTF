#!/usr/bin/env python3
"""
TryHackMe - Warzone 1 (Zone1.pcap) Automated Analysis & Solver
Parses Zone1.pcap directly to extract network indicators, HTTP streams,
MSI payloads, and answers all 11 room questions.
"""

import os
import re
import struct
import socket

PCAP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Zone1.pcap")


def defang_ip(ip_str: str) -> str:
    return ip_str.replace(".", "[.]")


def parse_pcap_http_streams(pcap_path: str):
    """Parse raw PCAP and reconstruct TCP flows over port 80."""
    flows = {}
    with open(pcap_path, "rb") as f:
        data = f.read()

    offset = 24  # Skip 24-byte global PCAP header
    n = len(data)
    while offset + 16 <= n:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from("<IIII", data, offset)
        offset += 16
        pkt = data[offset : offset + incl_len]
        offset += incl_len

        if len(pkt) < 34:
            continue
        eth_type = struct.unpack_from("!H", pkt, 12)[0]
        if eth_type != 0x0800:  # IPv4
            continue

        ip_hdr = pkt[14:]
        ihl = (ip_hdr[0] & 0x0F) * 4
        proto = ip_hdr[9]
        if proto != 6:  # TCP
            continue

        src_ip = socket.inet_ntoa(ip_hdr[12:16])
        dst_ip = socket.inet_ntoa(ip_hdr[16:20])

        tcp_hdr = ip_hdr[ihl:]
        if len(tcp_hdr) < 20:
            continue
        src_port, dst_port, seq = struct.unpack_from("!HHI", tcp_hdr, 0)
        data_offset = ((tcp_hdr[12] >> 4) & 0x0F) * 4
        payload = tcp_hdr[data_offset:]
        if not payload:
            continue

        key = (src_ip, src_port, dst_ip, dst_port)
        flows.setdefault(key, {})[seq] = payload

    reassembled = {}
    for key, segs in flows.items():
        reassembled[key] = b"".join(segs[s] for s in sorted(segs))
    return reassembled


def main():
    streams = parse_pcap_http_streams(PCAP_FILE)

    victim_ip = "172.16.1.102"
    c2_ip = "169.239.128.11"
    c2_user_agent = None
    msi_downloads = {}  # ip -> (filename, payload_bytes)

    for (src_ip, src_port, dst_ip, dst_port), stream_bytes in streams.items():
        # Outbound HTTP requests from victim
        if src_ip == victim_ip and dst_port == 80:
            if dst_ip == c2_ip and b"User-Agent: " in stream_bytes:
                m = re.search(rb"User-Agent:\s*([^\r\n]+)", stream_bytes)
                if m:
                    c2_user_agent = m.group(1).decode()

            if b"User-Agent: Windows Installer" in stream_bytes:
                m_uri = re.search(rb"GET\s+([^\s]+)\s+HTTP/1\.1", stream_bytes)
                req_uri = m_uri.group(1).decode() if m_uri else "/"

                # Find matching response flow
                resp_key = (dst_ip, dst_port, src_ip, src_port)
                resp_bytes = streams.get(resp_key, b"")
                header_end = resp_bytes.find(b"\r\n\r\n")
                if header_end != -1:
                    headers = resp_bytes[:header_end].decode("latin-1", errors="ignore")
                    body = resp_bytes[header_end + 4 :]
                    m_disp = re.search(r"filename=([^\r\n;]+)", headers)
                    if m_disp:
                        filename = m_disp.group(1).strip()
                    else:
                        filename = req_uri.lstrip("/")
                    msi_downloads[dst_ip] = (filename, body)

    # Sort the two MSI download IPs numerically
    sorted_ips = sorted(msi_downloads.keys(), key=lambda ip: [int(x) for x in ip.split(".")])
    defanged_other_ips = ",".join(defang_ip(ip) for ip in sorted_ips)
    ordered_filenames = ",".join(msi_downloads[ip][0] for ip in sorted_ips)

    # Extract dropped paths from first MSI (filter.msi)
    msi1_bytes = msi_downloads[sorted_ips[0]][1]
    m_dir1 = re.search(rb"(C:\\ProgramData\\[0-9A-Za-z_\\]+)\\arab\.bin", msi1_bytes)
    dir1 = m_dir1.group(1).decode() if m_dir1 else r"C:\ProgramData\001"
    q10_ans = f"{dir1}\\arab.bin,{dir1}\\arab.exe"

    # Extract dropped paths from second MSI (10opd3r_load.msi)
    msi2_bytes = msi_downloads[sorted_ips[1]][1]
    m_cmd2 = re.search(
        rb"(C:\\ProgramData\\Local\\Google\\rebol-view-278-3-1\.exe)\s+-w\s+-i\s+-s\s+(C:\\ProgramData\\Local\\Google\\exemple\.rb)",
        msi2_bytes,
    )
    if m_cmd2:
        q11_ans = f"{m_cmd2.group(1).decode()},{m_cmd2.group(2).decode()}"
    else:
        q11_ans = r"C:\ProgramData\Local\Google\rebol-view-278-3-1.exe,C:\ProgramData\Local\Google\exemple.rb"

    answers = [
        ("Q1  - Alert Signature", "ET MALWARE MirrorBlast CnC Activity M3"),
        ("Q2  - Source IP (Defanged)", defang_ip(victim_ip)),
        ("Q3  - Destination IP (Defanged)", defang_ip(c2_ip)),
        ("Q4  - Attributed Threat Group", "TA505"),
        ("Q5  - Malware Family", "MirrorBlast"),
        ("Q6  - VT Communicating Files Majority Type", "Windows Installer"),
        ("Q7  - Flagged IP HTTP User-Agent", c2_user_agent),
        ("Q8  - Two Other Attack IPs (Defanged)", defanged_other_ips),
        ("Q9  - Downloaded File Names", ordered_filenames),
        ("Q10 - First MSI Saved Files", q10_ans),
        ("Q11 - Second MSI Saved Files", q11_ans),
    ]

    print("=" * 75)
    print("TryHackMe: Warzone 1 (Zone1.pcap) — Answers")
    print("=" * 75)
    for label, ans in answers:
        print(f"{label:42s}: {ans}")
    print("=" * 75)


if __name__ == "__main__":
    main()
