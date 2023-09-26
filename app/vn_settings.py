# Parameters to customize virtual network simulation
vn_hosts = 5                        # No. of hosts ranges from 2 ~ 9
vn_duration = 1000                  # Duration in seconds

# Parameters of generate packet injection file for virtual network simulation
pkt_injection_type = 'sequential'   # sequential or random
inj_flows_count = 200               # No. of flow generated
injection_ratio = [10, 5]           # Ratio of Mice and Elephant Packets i.e [Mice, Elephant] = Mice : Elephant

# pkt_injection_time = 0.05           # This is a range starts from 0. Packets injected within this range at random interval.