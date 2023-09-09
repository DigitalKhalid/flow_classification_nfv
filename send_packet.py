import subprocess

# Define the hping3 command as a list of arguments
hping3_cmd = [
    "hping3",
    "-c", "1",                          # Send 1 packet
    "--file", "/home/mininet/elephants_1.pcap",           # Pkt File
    "10.0.0.3"                          # Replace with the IP address of h2
]

# Run the hping3 command on h1
try:
    subprocess.run(hping3_cmd, check=True)
    print("Packet sent successfully!")

except subprocess.CalledProcessError as e:
    print(f"Error: {e}")