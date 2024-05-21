# NetworkOverseer
This script utilizies nmap and ninjaone to locate unknown/unmanaged devices on a network.

It first starts by performing an nmap ping scan on a specified target network.

Next, it connects to the NinjaOne api and retrieves all device information available.

Finally, it compares the nmap data with the Ninja data.
- Any mac address that is found in NinjaOne is considered a known device
- Any mac address not found in NinjaOne is considered an unknown device

You can use the resulting $overseer object to send to an api, csv, or email a simple report of known and unknown devices.
