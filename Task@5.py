import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("700x500")

        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state='disabled')
        self.stop_button.pack(pady=5)

        self.text_area = ScrolledText(root, state='disabled', wrap=tk.WORD)
        self.text_area.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        self.sniff_thread = None
        self.sniffing = False
        self.log_file = "packet_log.txt"

    def log_packet(self, packet):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto

            protocol = {6: "TCP", 17: "UDP"}.get(proto, str(proto))

            info = f"\n[{timestamp}] {protocol} Packet:\nFrom: {src_ip} --> To: {dst_ip}\n"

            if TCP in packet or UDP in packet:
                l4 = packet[TCP] if TCP in packet else packet[UDP]
                info += f"Src Port: {l4.sport} --> Dst Port: {l4.dport}\n"

            if Raw in packet:
                data = packet[Raw].load
                try:
                    data_preview = data[:100].decode(errors='replace')
                    info += f"Payload (truncated): {data_preview}\n"
                except Exception:
                    info += "Payload (truncated): <could not decode>\n"

            self.append_text(info)
            self.save_to_file(info)

    def append_text(self, text):
        self.text_area.configure(state='normal')
        self.text_area.insert(tk.END, text)
        self.text_area.see(tk.END)
        self.text_area.configure(state='disabled')

    def save_to_file(self, text):
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(text)

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')
            self.append_text("\n--- Packet sniffing started ---\n")
            self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.sniff_thread.start()

    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            self.start_button.config(state='normal')
            self.stop_button.config(state='disabled')
            self.append_text("\n--- Packet sniffing stopped ---\n")

    def sniff_packets(self):
        # sniff with stop_filter to stop sniffing gracefully
        sniff(filter="ip", prn=self.log_packet, store=0, stop_filter=lambda x: not self.sniffing)

def main():
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
