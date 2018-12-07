Source files at https://github.com/mithilgotarne/sdnproject.git

1. Make sure sdnproject\src\main\resources\META-INF\services\net.floodlightcontroller.core.module.IFloodlightModule 
contains our module: net.floodlightcontroller.arppacketinspector.ARPPacketInspector

2. Compile floodlght (for example, running ant from within sdnproject directory)

3. Run the created jar file of floodlight controller with: java -jar floodlight.jar

4. Make sure mininet can specify eth and arp fields (for example, install nping)

5. Connect to controller when creating your mininet topology: 
sudo mn -controller=remote,ip=[yourIP],port=6653 --switch ovsk,protocols=OpneFlow13
where [yourIP] is the IP of the machine running the floodlight controller.

6. Create spoofed arp packet -
Ex: mininet> h1 sudo nping --source-mac [notYourMac] --arp-type ARP --arp-sender-mac [yourMac]
where [yourMac] is the MAC of h1 and notYourMac is a different MAC. 

7. Check mininet result -
Example nping result: 1 sent, 0 received, 1 lost

8. Check controller log -
Ex: [n.f.a.ARPPacketInspector] Spoof Rule 1 Triggered


