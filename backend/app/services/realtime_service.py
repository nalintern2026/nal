"""
Realtime / Active Monitoring Service.
Captures packets, builds flows, classifies via decision engine, inserts into DB.
Runs in background thread; never blocks FastAPI event loop.
"""
import logging
import threading
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# Max packets per capture window to avoid memory exhaustion
MAX_PACKETS_PER_WINDOW = 50000

# Protocol number to name mapping
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
    132: "SCTP",
}


def _get_protocol_name(num: int) -> str:
    return PROTOCOL_MAP.get(int(num) if num is not None else 0, str(num) if num else "Unknown")


# Throttle repeated capture failures (log at most once per 30s)
_capture_fail_log_time = 0.0
_capture_fail_count = 0
_last_capture_error: Optional[str] = None


def capture_packets(interface: Optional[str], duration: float = 5) -> List[Any]:
    """Capture packets using scapy. Returns list of packets.
    Run backend with sudo for packet sniffing.
    If specified interface not found, falls back to default (iface=None)."""
    global _capture_fail_log_time, _capture_fail_count, _last_capture_error
    try:
        from scapy.all import sniff
    except ImportError:
        _last_capture_error = "scapy not installed. pip install scapy"
        logger.error(_last_capture_error)
        return []

    # Default/auto: use loopback so we capture local API traffic (frontend↔backend)
    raw = (interface or "").strip()
    iface = raw if raw else "lo"

    try:
        packets = sniff(
            iface=iface,
            timeout=duration,
            count=MAX_PACKETS_PER_WINDOW,
        )
        _last_capture_error = None  # clear on success
        return list(packets) if packets else []
    except Exception as e:
        err_str = str(e).lower()
        # If interface not found, retry with default (captures on all/default interfaces)
        if iface and ("not found" in err_str or "no such device" in err_str):
            try:
                packets = sniff(iface=None, timeout=duration, count=MAX_PACKETS_PER_WINDOW)
                import time
                if time.time() - _capture_fail_log_time > 30:
                    logger.warning(
                        f"Interface '{iface}' not found, using default. "
                        "Pick an interface from the list on the Active Monitoring page."
                    )
                    _capture_fail_log_time = time.time()
                _last_capture_error = None  # clear on success
                return list(packets) if packets else []
            except Exception as e2:
                import time
                _capture_fail_count += 1
                _last_capture_error = str(e2)
                if time.time() - _capture_fail_log_time > 30:
                    logger.warning(f"Packet capture failed (retry): {e2}")
                    _capture_fail_log_time = time.time()
                return []
        # Throttle log spam for repeated failures (e.g. permission denied)
        import time
        _capture_fail_count += 1
        _last_capture_error = str(e)
        if time.time() - _capture_fail_log_time > 30:
            logger.warning(f"Packet capture failed: {e}")
            _capture_fail_log_time = time.time()
        return []


def _stats(vals):
    """Return (max, min, mean, std) for a list of numbers."""
    import numpy as _np
    if not vals:
        return 0.0, 0.0, 0.0, 0.0
    a = _np.array(vals, dtype=float)
    return float(a.max()), float(a.min()), float(a.mean()), float(a.std())


def _iat(timestamps):
    """Return inter-arrival times from sorted timestamps."""
    if len(timestamps) < 2:
        return []
    s = sorted(timestamps)
    return [s[i + 1] - s[i] for i in range(len(s) - 1)]


def build_flows_from_packets(packets: List[Any]) -> List[Dict[str, Any]]:
    """
    Group packets by 5-tuple, compute all 79 CIC-style features for the ML model.
    Returns list of flow dicts with snake_case keys matching feature_names.pkl.
    """
    if not packets:
        return []

    flows: Dict[tuple, Dict[str, Any]] = defaultdict(lambda: {
        "src_ip": None, "dst_ip": None, "src_port": 0, "dst_port": 0, "protocol_num": 6,
        "fwd_pkt_lens": [], "bwd_pkt_lens": [], "all_pkt_lens": [],
        "fwd_timestamps": [], "bwd_timestamps": [], "all_timestamps": [],
        "fwd_header_lens": [], "bwd_header_lens": [],
        "init_fwd_win": -1, "init_bwd_win": -1,
        "fin_cnt": 0, "syn_cnt": 0, "rst_cnt": 0, "psh_cnt": 0,
        "ack_cnt": 0, "urg_cnt": 0, "ece_cnt": 0, "cwr_cnt": 0,
        "fwd_psh": 0, "bwd_psh": 0, "fwd_urg": 0, "bwd_urg": 0,
        "fwd_act_data": 0,
    })

    for pkt in packets:
        try:
            if not hasattr(pkt, "payload"):
                continue
            if pkt.haslayer("IP"):
                ip_layer = pkt["IP"]
            elif pkt.haslayer("IPv6"):
                ip_layer = pkt["IPv6"]
            else:
                continue
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)

            src_port, dst_port = 0, 0
            protocol_num = 0
            tcp_flags = 0
            tcp_window = 0
            header_len = 0

            if pkt.haslayer("TCP"):
                protocol_num = 6
                tcp = pkt["TCP"]
                src_port = int(tcp.sport) if tcp.sport else 0
                dst_port = int(tcp.dport) if tcp.dport else 0
                tcp_flags = int(tcp.flags) if hasattr(tcp, "flags") and tcp.flags else 0
                tcp_window = int(tcp.window) if hasattr(tcp, "window") else 0
                header_len = int(tcp.dataofs or 5) * 4
            elif pkt.haslayer("UDP"):
                protocol_num = 17
                udp = pkt["UDP"]
                src_port = int(udp.sport) if udp.sport else 0
                dst_port = int(udp.dport) if udp.dport else 0
                header_len = 8
            elif pkt.haslayer("ICMP"):
                protocol_num = 1
                header_len = 8
            else:
                continue

            pkt_len = len(pkt)
            ts = float(pkt.time) if hasattr(pkt, "time") else 0.0
            payload_len = pkt_len - header_len if pkt_len > header_len else 0

            src_tup = (src_ip, src_port)
            dst_tup = (dst_ip, dst_port)
            if src_tup <= dst_tup:
                key = (src_ip, dst_ip, src_port, dst_port, protocol_num)
                fwd = True
            else:
                key = (dst_ip, src_ip, dst_port, src_port, protocol_num)
                fwd = False

            f = flows[key]
            if f["src_ip"] is None:
                f["src_ip"] = key[0]
                f["dst_ip"] = key[1]
                f["src_port"] = key[2]
                f["dst_port"] = key[3]
                f["protocol_num"] = protocol_num

            f["all_pkt_lens"].append(pkt_len)
            f["all_timestamps"].append(ts)

            if fwd:
                f["fwd_pkt_lens"].append(pkt_len)
                f["fwd_timestamps"].append(ts)
                f["fwd_header_lens"].append(header_len)
                if f["init_fwd_win"] == -1:
                    f["init_fwd_win"] = tcp_window
                if payload_len > 0:
                    f["fwd_act_data"] += 1
                if tcp_flags & 0x08:
                    f["fwd_psh"] += 1
                if tcp_flags & 0x20:
                    f["fwd_urg"] += 1
            else:
                f["bwd_pkt_lens"].append(pkt_len)
                f["bwd_timestamps"].append(ts)
                f["bwd_header_lens"].append(header_len)
                if f["init_bwd_win"] == -1:
                    f["init_bwd_win"] = tcp_window
                if tcp_flags & 0x08:
                    f["bwd_psh"] += 1
                if tcp_flags & 0x20:
                    f["bwd_urg"] += 1

            if tcp_flags & 0x01: f["fin_cnt"] += 1
            if tcp_flags & 0x02: f["syn_cnt"] += 1
            if tcp_flags & 0x04: f["rst_cnt"] += 1
            if tcp_flags & 0x08: f["psh_cnt"] += 1
            if tcp_flags & 0x10: f["ack_cnt"] += 1
            if tcp_flags & 0x20: f["urg_cnt"] += 1
            if tcp_flags & 0x40: f["ece_cnt"] += 1
            if tcp_flags & 0x80: f["cwr_cnt"] += 1

        except Exception:
            continue

    result = []
    for key, f in flows.items():
        if not f["all_timestamps"]:
            continue

        dur = max(f["all_timestamps"]) - min(f["all_timestamps"]) if len(f["all_timestamps"]) > 1 else 0
        dur_safe = max(dur, 0.000001)

        tot_fwd = len(f["fwd_pkt_lens"])
        tot_bwd = len(f["bwd_pkt_lens"])
        tot_pkts = tot_fwd + tot_bwd
        totlen_fwd = sum(f["fwd_pkt_lens"])
        totlen_bwd = sum(f["bwd_pkt_lens"])
        total_bytes = totlen_fwd + totlen_bwd

        fwd_max, fwd_min, fwd_mean, fwd_std = _stats(f["fwd_pkt_lens"])
        bwd_max, bwd_min, bwd_mean, bwd_std = _stats(f["bwd_pkt_lens"])
        all_max, all_min, all_mean, all_std = _stats(f["all_pkt_lens"])
        import numpy as _np
        all_var = float(_np.var(f["all_pkt_lens"])) if f["all_pkt_lens"] else 0.0

        flow_iats = _iat(f["all_timestamps"])
        fwd_iats = _iat(f["fwd_timestamps"])
        bwd_iats = _iat(f["bwd_timestamps"])

        fi_max, fi_min, fi_mean, fi_std = _stats(flow_iats)
        fwdi_max, fwdi_min, fwdi_mean, fwdi_std = _stats(fwd_iats)
        bwdi_max, bwdi_min, bwdi_mean, bwdi_std = _stats(bwd_iats)

        down_up = (tot_bwd / tot_fwd) if tot_fwd > 0 else 0.0

        flow_dict = {
            "src_ip": str(f["src_ip"]),
            "dst_ip": str(f["dst_ip"]),
            "src_port": f["src_port"],
            "dst_port": f["dst_port"],
            "protocol": _get_protocol_name(f["protocol_num"]),
            "protocol_num": f["protocol_num"],
            "flow_duration": dur * 1e6,
            "flow_byts_s": total_bytes / dur_safe,
            "flow_pkts_s": tot_pkts / dur_safe,
            "fwd_pkts_s": tot_fwd / dur_safe,
            "bwd_pkts_s": tot_bwd / dur_safe,
            "tot_fwd_pkts": tot_fwd,
            "tot_bwd_pkts": tot_bwd,
            "totlen_fwd_pkts": totlen_fwd,
            "totlen_bwd_pkts": totlen_bwd,
            "fwd_pkt_len_max": fwd_max, "fwd_pkt_len_min": fwd_min,
            "fwd_pkt_len_mean": fwd_mean, "fwd_pkt_len_std": fwd_std,
            "bwd_pkt_len_max": bwd_max, "bwd_pkt_len_min": bwd_min,
            "bwd_pkt_len_mean": bwd_mean, "bwd_pkt_len_std": bwd_std,
            "pkt_len_max": all_max, "pkt_len_min": all_min,
            "pkt_len_mean": all_mean, "pkt_len_std": all_std,
            "pkt_len_var": all_var,
            "fwd_header_len": sum(f["fwd_header_lens"]),
            "bwd_header_len": sum(f["bwd_header_lens"]),
            "fwd_seg_size_min": min(f["fwd_pkt_lens"]) if f["fwd_pkt_lens"] else 0,
            "fwd_act_data_pkts": f["fwd_act_data"],
            "flow_iat_mean": fi_mean * 1e6, "flow_iat_max": fi_max * 1e6,
            "flow_iat_min": fi_min * 1e6, "flow_iat_std": fi_std * 1e6,
            "fwd_iat_tot": sum(fwd_iats) * 1e6 if fwd_iats else 0,
            "fwd_iat_max": fwdi_max * 1e6, "fwd_iat_min": fwdi_min * 1e6,
            "fwd_iat_mean": fwdi_mean * 1e6, "fwd_iat_std": fwdi_std * 1e6,
            "bwd_iat_tot": sum(bwd_iats) * 1e6 if bwd_iats else 0,
            "bwd_iat_max": bwdi_max * 1e6, "bwd_iat_min": bwdi_min * 1e6,
            "bwd_iat_mean": bwdi_mean * 1e6, "bwd_iat_std": bwdi_std * 1e6,
            "fwd_psh_flags": f["fwd_psh"], "bwd_psh_flags": f["bwd_psh"],
            "fwd_urg_flags": f["fwd_urg"], "bwd_urg_flags": f["bwd_urg"],
            "fin_flag_cnt": f["fin_cnt"], "syn_flag_cnt": f["syn_cnt"],
            "rst_flag_cnt": f["rst_cnt"], "psh_flag_cnt": f["psh_cnt"],
            "ack_flag_cnt": f["ack_cnt"], "urg_flag_cnt": f["urg_cnt"],
            "ece_flag_cnt": f["ece_cnt"], "cwr_flag_count": f["cwr_cnt"],
            "down_up_ratio": down_up,
            "pkt_size_avg": total_bytes / max(tot_pkts, 1),
            "init_fwd_win_byts": f["init_fwd_win"] if f["init_fwd_win"] != -1 else 0,
            "init_bwd_win_byts": f["init_bwd_win"] if f["init_bwd_win"] != -1 else 0,
            "active_max": 0, "active_min": 0, "active_mean": 0, "active_std": 0,
            "idle_max": 0, "idle_min": 0, "idle_mean": 0, "idle_std": 0,
            "fwd_byts_b_avg": 0, "fwd_pkts_b_avg": 0,
            "bwd_byts_b_avg": 0, "bwd_pkts_b_avg": 0,
            "fwd_blk_rate_avg": 0, "bwd_blk_rate_avg": 0,
            "fwd_seg_size_avg": fwd_mean,
            "bwd_seg_size_avg": bwd_mean,
            "subflow_fwd_pkts": tot_fwd, "subflow_bwd_pkts": tot_bwd,
            "subflow_fwd_byts": totlen_fwd, "subflow_bwd_byts": totlen_bwd,
        }
        result.append(flow_dict)

    return result


class RealtimeMonitor:
    """Background thread for live packet capture and flow analysis."""

    def __init__(self):
        self.running = False
        self.interface: Optional[str] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._capture_count = 0
        self._last_flow_count = 0

    def start(self, interface: str) -> None:
        """Start monitoring in background thread."""
        with self._lock:
            if self.running:
                return
            self.running = True
            self.interface = interface or None
            self._thread = threading.Thread(
                target=self._run,
                args=(interface,),
                daemon=True,
            )
            self._thread.start()
            logger.info(f"Realtime monitor started on interface: {interface or 'default'}")

    def stop(self) -> None:
        """Stop monitoring."""
        with self._lock:
            self.running = False
        logger.info("Realtime monitor stopped")

    def _run(self, interface: str) -> None:
        """Main loop: capture -> build flows -> classify -> insert."""
        while self.running:
            try:
                packets = capture_packets(interface, duration=5)
                if not packets:
                    continue

                flows_raw = build_flows_from_packets(packets)
                if not flows_raw:
                    continue

                from app.services.decision_service import decision_engine
                from app import db

                enriched = decision_engine.classify_flows(flows_raw)
                if not enriched:
                    continue

                self._capture_count += 1
                self._last_flow_count = len(enriched)

                for f in enriched:
                    f["monitor_type"] = "active"
                    f["analysis_id"] = None
                    f["upload_filename"] = "realtime"
                    f["id"] = str(uuid.uuid4())[:8]
                    f["timestamp"] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S') + 'Z'

                db.insert_flows(enriched, monitor_type="active")
                logger.info(f"Inserted {len(enriched)} active flows from {len(packets)} packets")

            except Exception as e:
                logger.error(f"Realtime monitor loop error: {e}", exc_info=True)
                # Continue to next iteration

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "running": self.running,
                "interface": self.interface if self.interface else "lo (default)",
                "capture_count": self._capture_count,
                "last_flow_count": self._last_flow_count,
                "capture_error": _last_capture_error,
            }


# Global singleton
realtime_monitor = RealtimeMonitor()
