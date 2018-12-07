
Make sure sdnproject\src\main\resources\META-INF\services\net.floodlightcontroller.core.module.IFloodlightModule 
contains our module: net.floodlightcontroller.arppacketinspector.ARPPacketInspector

Compile floodlght (for example, running ant from within sdnproject directory)

Run the created jar file of floodlight controller with: java -jar floodlight.jar

Make sure mininet can specify eth and arp fields (for example, install nping)

Connect to controller when creating your mininet topology: 
sudo mn -controller=remote,ip=[yourIP],port=6653 --switch ovsk,protocols=OpneFlow13
where [yourIP] is the IP of the machine running the floodlight controller.

Create spoofed arp packet -
Ex: mininet> h1 sudo nping --source-mac [notYourMac] --arp-type ARP --arp-sender-mac [yourMac]
where [yourMac] is the MAC of h1 and notYourMac is a different MAC. 

Check mininet result -
Ex: 1 sent, 0 received, 1 lost

Check controller log -
Ex: [n.f.a.ARPPacketInspector] Spoof Rule 1 Triggered


