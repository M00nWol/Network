# gui_interface.py

import tkinter as tk
from capture_packets import start_capture

# GUI setting
def start_sniffing():
    packet_count = int(packet_count_entry.get())
    protocol_filter = filter_entry.get()
    start_capture(count=packet_count, filter=protocol_filter)

root = tk.Tk()
root.title("Packet Capture Tool")

packet_count_label = tk.Label(root, text="Number of Packets: ")
packet_count_label.pack()

packet_count_entry = tk.Entry(root)
packet_count_entry.pack()

filter_label = tk.Label(root, text="Protocol Fileter (e.g., tcp, udp): ")
filter_label.pack()

filter_entry = tk.Entry(root)
filter_entry.pack()

start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing)
start_button.pack()

root.mainloop()