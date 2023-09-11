import subprocess

# Define the hping3 command as a list of arguments
hping3_cmd = [
    "hping3",
    "-c", "1",          # Send 1 packet
    "-p", "80",         # Destination Port
    "-s", "2546",       # Source Port
    "-d", "64",         # Replace with the desired packet size
    "-I", "s1-eth1"     # Interface Name
    "-E", "Hello",      # Replace with the custom payload
    "-2",                # Default is TCP, -0 is RawIP, -1 is ICMP, -2 is UDP
    "10.0.0.2"          # Replace with the IP address of h2
]

# Run the hping3 command on h1
try:
    subprocess.run(hping3_cmd, check=True)
    print("Packet sent successfully!")
except subprocess.CalledProcessError as e:
    print(f"Error: {e}")
