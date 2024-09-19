import tkinter as tk
from threading import Thread
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from capture_packets import start_capture, time_values, tcp_values, udp_values, icmp_values

# GUI-related functions
def start_sniffing():
    packet_count = int(packet_count_entry.get())
    protocol_filter = filter_entry.get()

    # If filter is empty, set it to a default value
    if not protocol_filter:
        protocol_filter = "ip"  # Default filter to capture all IP packets

    # Start packet capture in a new thread
    capture_thread = Thread(target=start_capture, args=(packet_count, protocol_filter))
    capture_thread.start()

    # Start visualization
    start_visualization()

def start_visualization():
    # Initialize Matplotlib figure for visualization
    plt.style.use('fivethirtyeight')
    fig, ax = plt.subplots()
    line_tcp, = ax.plot([], [], label='TCP', color='blue')
    line_udp, = ax.plot([], [], label='UDP', color='green')
    line_icmp, = ax.plot([], [], label='ICMP', color='red')
    ax.legend()

    def update(frame):
        # Update line data
        line_tcp.set_data(time_values, tcp_values)
        line_udp.set_data(time_values, udp_values)
        line_icmp.set_data(time_values, icmp_values)

        # Adjust plot limits
        ax.set_xlim(0, len(time_values))
        ax.set_ylim(0, max(max(tcp_values, default=0), max(udp_values, default=0), max(icmp_values, default=0)) + 5)
        return line_tcp, line_udp, line_icmp

    # Start the animation
    ani = FuncAnimation(fig, update, blit=True)
    plt.show()

# GUI setup
root = tk.Tk()
root.title("Packet Capture Tool with Visualization")

packet_count_label = tk.Label(root, text="Number of Packets: ")
packet_count_label.pack()

packet_count_entry = tk.Entry(root)
packet_count_entry.pack()

filter_label = tk.Label(root, text="Protocol Filter (e.g., tcp, udp): ")
filter_label.pack()

filter_entry = tk.Entry(root)
filter_entry.pack()

start_button = tk.Button(root, text="Start Sniffing and Visualizing", command=start_sniffing)
start_button.pack()

root.mainloop()