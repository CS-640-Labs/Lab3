package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.MACAddress;

import java.nio.ByteBuffer;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;



/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	/** ARP packet queue */
	private  Map<Integer, ArpQueue> arpQueueMap;

	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.arpQueueMap = new ConcurrentHashMap<Integer, ArpQueue>() {
		};
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }

	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}

		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/
		/* TODO: Handle packets                                             */

		switch(etherPacket.getEtherType())
		{
			case Ethernet.TYPE_IPv4:
				this.handleIpPacket(etherPacket, inIface);
				break;
			case Ethernet.TYPE_ARP:
				this.handleArpPacket(etherPacket, inIface);
				break;
		}

		/********************************************************************/
	}

	private void handleArpPacket(Ethernet etherPacket, Iface inIface) {
		// Get ARP header
		ARP arpPacket = (ARP)etherPacket.getPayload();

		// get target ip protocol
		int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();

		System.out.println("Handle ARP packet");

		// if an ARP packet is an ARP request
		if(arpPacket.getOpCode() == ARP.OP_REQUEST) {
			System.out.println("ARP Request: " + IPv4.fromIPv4Address(IPv4.toIPv4Address(arpPacket.getSenderProtocolAddress())));
			// if target ip is equal to interfaced packet was received
			if(targetIp == inIface.getIpAddress()) {

				// create ethernet header
				Ethernet etherHeader = new Ethernet();
				etherHeader.setEtherType(Ethernet.TYPE_ARP);
				etherHeader.setSourceMACAddress(inIface.getMacAddress().toBytes());
				etherHeader.setDestinationMACAddress(etherPacket.getSourceMACAddress());

				// create ARP header
				ARP arpHeader = new ARP();
				arpHeader.setHardwareType(ARP.HW_TYPE_ETHERNET);
				arpHeader.setProtocolType(ARP.PROTO_TYPE_IP);
				arpHeader.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
				arpHeader.setProtocolAddressLength((byte) 4);
				arpHeader.setOpCode(ARP.OP_REPLY);
				arpHeader.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
				arpHeader.setSenderProtocolAddress(inIface.getIpAddress());
				arpHeader.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
				arpHeader.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());

				// link headers
				etherHeader.setPayload(arpHeader);

				// send packet back
				this.sendPacket(etherHeader, inIface);
			}
		}
		// if received an arp reply
		else if(arpPacket.getOpCode() == ARP.OP_REPLY) {
			System.out.println("ARP Reply: " + IPv4.fromIPv4Address(IPv4.toIPv4Address(arpPacket.getSenderProtocolAddress())));
			// add to arp cache
			arpCache.insert(MACAddress.valueOf(arpPacket.getSenderHardwareAddress()), IPv4.toIPv4Address(arpPacket.getSenderProtocolAddress()));
			ArpQueue arpQueue = arpQueueMap.get(IPv4.toIPv4Address(arpPacket.getSenderProtocolAddress()));
			System.out.println(arpCache);

			if (arpQueue != null) {
				arpQueue.dequeuePackets(arpPacket.getSenderHardwareAddress(), inIface);
			}
		}

	}

	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// if not an IP packet then drop
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) { return; }

		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		System.out.println("Handle IP packet");

		// Verify checksum
		short origCksum = ipPacket.getChecksum();
		ipPacket.resetChecksum();
		byte[] serialized = ipPacket.serialize();
		ipPacket.deserialize(serialized, 0, serialized.length);
		short calcCksum = ipPacket.getChecksum();
		if (origCksum != calcCksum)
		{ return; }

		// Check TTL
		ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
		if (0 == ipPacket.getTtl())
		{
			generateICMP(ipPacket,inIface,11,0);
			return;
		}

		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();

		// Check if packet is destined for one of router's interfaces
		for (Iface iface : this.interfaces.values())
		{
			if (ipPacket.getDestinationAddress() == iface.getIpAddress())
			{
				if(ipPacket.getProtocol()== IPv4.PROTOCOL_UDP || ipPacket.getProtocol()== IPv4.PROTOCOL_TCP ){
					generateICMP(ipPacket,inIface,3,3);
				}
				if(ipPacket.getProtocol() == IPv4.PROTOCOL_ICMP){
					ICMP icmp = (ICMP)(ipPacket.getPayload());
					if(icmp.getIcmpType() == ((byte)(8))){

						generateICMP(ipPacket,inIface,0,0);
					}
				}
				return; }
		}

		// Do route lookup and forward
		this.forwardIpPacket(etherPacket, inIface);
	}

	public void generateICMP(IPv4 ipPacket, Iface inIface,int icmpType,int icmpCode){
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		ICMP icmp = new ICMP();
		Data data = new Data();
		byte temp = ip.getTtl();
		ipPacket.setTtl((byte)(ipPacket.getTtl()+1));
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(inIface.getMacAddress().toString()); //perhaps wrong
		ip.setTtl((byte)(64));
		ip.setProtocol((byte)(IPv4.PROTOCOL_ICMP));

		ip.setSourceAddress(inIface.getIpAddress());
		if((icmpType== 0) && (icmpCode==0)){
			ip.setSourceAddress(ipPacket.getDestinationAddress());
		}
		ip.setDestinationAddress(ipPacket.getSourceAddress());
		icmp.setIcmpType((byte)(icmpType));
		icmp.setIcmpCode((byte)(icmpCode));
		ip.resetChecksum();
		byte[] data_ip = ipPacket.serialize();
		int ip_header_length = ipPacket.getHeaderLength()*4;
		byte[] bytes1 = new byte[4+ip_header_length+8];
		for(int i=0;i<ip_header_length+8;i++){
			bytes1[4+i]=data_ip[i];
		}
		data.setData(bytes1);
		icmp.setPayload(data);
		ip.setPayload(icmp);
		ether.setPayload(ip);
		RouteEntry bestMatch = this.routeTable.lookup(ipPacket.getSourceAddress());
		// if(bestMatch!=null){
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop)
		{ nextHop = ipPacket.getSourceAddress(); }
		ArpEntry arp_entry = this.arpCache.lookup(nextHop);
		if(arp_entry==null){
			System.out.println("arp entry is null, could not find: " + IPv4.fromIPv4Address(nextHop));
			sendArpRequest(ether,inIface);
		}
		else{
		ether.setDestinationMACAddress(arp_entry.getMac().toString());
		this.sendPacket(ether, inIface);
		}
		// }
	}

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		System.out.println("Forward IP packet");

		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
		int dstAddr = ipPacket.getDestinationAddress();

		// Find matching route table entry
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

		// If no entry matched, do nothing
		if (null == bestMatch)
		{
			generateICMP(ipPacket,inIface,3,0);
			return; }

		// Make sure we don't sent a packet back out the interface it came in
		Iface outIface = bestMatch.getInterface();
		if (outIface == inIface) { return; }

		// Set source MAC address in Ethernet header
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop)
		{ nextHop = dstAddr; }

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);

		if (null == arpEntry) {
			sendArpRequest(etherPacket, inIface);
			return;
		}
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

		System.out.println("Forwarding packet");
		this.sendPacket(etherPacket, outIface);
	}

	void sendArpRequest(Ethernet etherPacket, Iface inIface) {
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();

		// if ip queue doesnt exist -> create queue and start timout
		if(!arpQueueMap.containsKey(ipPacket.getDestinationAddress())) {
			// create ethernet header
			Ethernet etherHeader = new Ethernet();
			etherHeader.setEtherType(Ethernet.TYPE_ARP);
			etherHeader.setSourceMACAddress(inIface.getMacAddress().toBytes());
			etherHeader.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");

			// create ARP header
			ARP arpHeader = new ARP();
			arpHeader.setHardwareType(ARP.HW_TYPE_ETHERNET);
			arpHeader.setProtocolType(ARP.PROTO_TYPE_IP);
			arpHeader.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
			arpHeader.setProtocolAddressLength((byte) 4);
			arpHeader.setOpCode(ARP.OP_REQUEST);
			arpHeader.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
			arpHeader.setSenderProtocolAddress(inIface.getIpAddress());
			byte [] b = new byte[10];
			arpHeader.setTargetHardwareAddress(b);
			arpHeader.setTargetProtocolAddress(ipPacket.getDestinationAddress());

			// link headers
			etherHeader.setPayload(arpHeader);
			arpQueueMap.put(ipPacket.getDestinationAddress(), new ArpQueue(etherHeader, this, inIface));
			System.out.println("Create new queue");
		}

		// add packet to queue
		arpQueueMap.get(ipPacket.getDestinationAddress()).insert(etherPacket);
		System.out.println("Add to queue");
	}
}
