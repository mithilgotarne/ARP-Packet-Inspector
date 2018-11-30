package net.floodlightcontroller.arppacketinspector;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.Device;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.*;


import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ARP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ARPPacketInspector implements IOFMessageListener, IFloodlightModule {

    protected IFloodlightProviderService floodlightProvider;
    protected static Logger logger;

    @Override
    public String getName() {
        // TODO Auto-generated method stub
        return ARPPacketInspector.class.getSimpleName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        logger = LoggerFactory.getLogger(ARPPacketInspector.class);
    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
    }

    /*
     * Overridden IOFMessageListener's receive() function.
     */
    @Override
    public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        switch (msg.getType()) {
            case PACKET_IN:
                /* Retrieve the deserialized packet in message */
                Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

                /* Various getters and setters are exposed in Ethernet */
//                MacAddress srcMac = eth.getSourceMACAddress();
//                VlanVid vlanId = VlanVid.ofVlan(eth.getVlanID());

                /*
                 * Check the ethertype of the Ethernet frame and retrieve the appropriate payload.
                 * Note the shallow equality check. EthType caches and reuses instances for valid types.
//                 */
//                if (eth.getEtherType() == EthType.IPv4) {
//                    /* We got an IPv4 packet; get the payload from Ethernet */
//                    IPv4 ipv4 = (IPv4) eth.getPayload();
//
//                    /* Various getters and setters are exposed in IPv4 */
//                    byte[] ipOptions = ipv4.getOptions();
//                    IPv4Address dstIp = ipv4.getDestinationAddress();
//
//                    /* Still more to come... */
//
//                } else

                logger.info("Eth MAC Address: {} seen on switch: {}", eth.getSourceMACAddress().toString(), sw.getId().toString());

                if (eth.getEtherType() == EthType.ARP) {
                    /* We got an ARP packet; get the payload from Ethernet */
                    ARP arp = (ARP) eth.getPayload();

                    /* Various getters and setters are exposed in ARP */
                    boolean gratuitous = arp.isGratuitous();

                    logger.info("ARP Sender Hardware Address: {} seen on switch: {}", arp.getSenderHardwareAddress().toString(), sw.getId().toString());

                    if(! (eth.getSourceMACAddress().equals( arp.getSenderHardwareAddress() ) ) ) { //Rule 1
                        logger.info("Spoof Rule 1 Triggered"); //spoofDetected
                        return Command.STOP; //Stop processing on the packet
                    }

                    logger.info("ARP Sender Protocol Address: {} seen on switch: {}", arp.getSenderProtocolAddress().toString(), sw.getId().toString());

                    //*search controller for device matching given MAC and IP pair. If it exists, returns it in the iterator. If not a valid pair, iterator will be empty.
                    try {
                        DeviceManagerImpl man = new DeviceManagerImpl();
                        Iterator senderIterator = man.queryDevices(arp.getSenderHardwareAddress(), null, arp.getSenderProtocolAddress(), //note arp ProtocolAddress is returning an IPv4 address
                                IPv6Address.NONE, DatapathId.NONE, OFPort.ZERO);
                        if (!senderIterator.hasNext()) {
                            logger.info("Spoof Rule 2 Triggered"); //spoofDetected
                            return Command.STOP; //Stop processing on the packet
                        }


                    if(arp.getOpCode() == ArpOpcode.REQUEST) {
                       if(!eth.isBroadcast()) { //Rule 3a, request should be a broadcast
                           logger.info("Spoof Rule 3a Triggered"); //spoofDetected
                           return Command.STOP; //Stop processing on the packet
                       }
                    } else if (arp.getOpCode().equals(ArpOpcode.REPLY)) {
                        if(eth.isBroadcast()) {  //Rule 3b, reply shouldn't be a broadcast
                            logger.info("Spoof Rule 3b Triggered"); //spoofDetected
                            return Command.STOP; //Stop processing on the packet
                        }

                        logger.info("ARP Target Hardware Address: {} seen on switch: {}", arp.getTargetHardwareAddress().toString(), sw.getId().toString());

                        if(! (eth.getDestinationMACAddress().equals( arp.getTargetHardwareAddress() ) ) ) { //Rule 4
                            logger.info("Spoof Rule 4 Triggered"); //spoofDetected
                            return Command.STOP; //Stop processing on the packet
                        }

                        logger.info("ARP Target Protocol Address: {} seen on switch: {}", arp.getTargetProtocolAddress().toString(), sw.getId().toString());

                        //*search controller for device matching given MAC and IP pair. If it exists, returns it in the iterator. If not a valid pair, iterator will be empty.
                        Iterator targetIterator = man.queryDevices(arp.getTargetHardwareAddress(), null, arp.getTargetProtocolAddress(), //note arp ProtocolAddress is returning an IPv4 address
                                IPv6Address.NONE, DatapathId.NONE, OFPort.ZERO);
                        if(!targetIterator.hasNext()) {
                            logger.info("Spoof Rule 5 Triggered");  //spoofDetected
                            return Command.STOP; //Stop processing on the packet
                        }

                    }

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                } else {
                    /* Unhandled ethertypes */
                }
                break;
            default:
                break;
        }
        return Command.CONTINUE; //pass packet to other modules to continue processing
    }
}