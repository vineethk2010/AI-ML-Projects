#!/usr/bin/env python3
"""
Module Docstring
"""
# capture.py
import threading
from scapy.all import sniff
from packet_processor import PacketProcessor

def start_packet_capture() -> PacketProcessor:
    """Start packet capture in a separate thread and return the PacketProcessor instance."""
    processor = PacketProcessor()

    def capture_packets():
        sniff(prn=processor.process_packet, store=False)

    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()

    return processor
