# Resource-Aware-Traffic-Steering-in-Service-Function-Chaining
----------------------------------------------------------------------------------------------
Resource Aware Traffic Steering in Service Function Chaining
----------------------------------------------------------------------------------------------
A Project for PhD research paper

----------------------------------------------------------------------------------------------
Pre-requisites to run virtual network simulation
----------------------------------------------------------------------------------------------
- Ubuntu 22.04.3 LTS
- Install Python 3.9.0 
    - Open the link below and follow the procedure to install:
      https://www.linuxcapable.com/how-to-install-python-3-9-on-ubuntu-linux/
      
- Open terminal and install following packages using root privileges:
    - Mininet, Pandas, Scapy, hping3, scikit-learn
        - sudo apt-get install mininet pandas scapy hping3 scikit-learn

- Make a new directory and sub directories as follows:
    - Paste following files in the main directory:
        - help.txt, README.md, requirements.txt, start.sh
    - Make sub directory named 'datasets' and paste data files in this directory
    - Make sub directory named 'models' and paste model files in this directory
    - Make sub directory named 'app' and paste all python files in this directory
    - Make empty sub directory named 'logs'

- Open terminal from the main directory
- Create virtual environment using command: python3.9 -m venv venv
- Active the virtual environment using command: source venv/bin/activate
- Now install other packages using command: python3 -m pip install -r requirements.txt

----------------------------------------------------------------------------------------------
Settings to customize virtual network simulation
----------------------------------------------------------------------------------------------
- You can customize simulation by changing the values of variables given in file: vn_settings.py
- There are following settings available for simulation:
    - vn_host
        - This is virtual network host created by mininet.
        - Default value is 5. You can set the value upto 9.

    - vn_duration (If packets in packet injection file ends up prior to this duration, simulation will stop.)
        - This is virtual network duration in seconds.
        - Default value is 30.

- There are following settings available for generation of packet injection file:
    You can generate packet injection file as per your requirements. This file will be used to inject packets during simulation.
    - pkt_injection_type
        - This defines how flows read from the source file.
        - There are two options available:
            - sequential
                - It will read the flow from source file in a sequenced manner.
            - random
                - It will rea the flow from the source file in a random order.

    - injection_flows_count:
        - Total number of flows generated for packet injection file.

    - injection_ratio
        - This is the ratio between mice packets and elephant packets.
        - Default value is [10, 1] means mice packets:elephant packets = 10:1

----------------------------------------------------------------------------------------------
How to run virtual network?
----------------------------------------------------------------------------------------------
- Open the terminal from the same directory.
- Use command: ./start.sh (Its needs root pervilages hence asked for password.)
- This command will do the following:
    - Run Mininet Cleanup to remove previous instance of virtual network if any.
    - Run Ryu Rest API.
    - Start Ryu Controller.
    - Create a network topology.
    - Start Injecting Packets to the network.
    - The whole process will run for a specificed period of time and then stops.
    - Create log file for packet injection.
    - Create log file for flow classification (Remove duplicate values if any).
    - Create summary file. Log files and summary files will be created in logs folder.

----------------------------------------------------------------------------------------------
Asumptions
----------------------------------------------------------------------------------------------
- We are sending flows from the dataset extracted from the MAWI packet trace data.
- We have actual classification in the dataset by which we can measure the outputs and compares the actual flows vs classified flows.

----------------------------------------------------------------------------------------------
Packet Capturing
----------------------------------------------------------------------------------------------
You can capture the packets using WireShark. Open WireShark using following command:
   - sudo wireshark

----------------------------------------------------------------------------------------------
Thank you.
For more information, please email: po.mwts@gmail.com
----------------------------------------------------------------------------------------------
