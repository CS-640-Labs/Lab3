package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.*;

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

	public void runRIP() {

		// init connected hosts
		for(Iface iface :  this.getInterfaces().values()) {
			int destinationAddress = iface.getIpAddress() & iface.getSubnetMask();
			int gatewayAddress = 0;
			int maskAddress = iface.getSubnetMask();
			this.routeTable.insert(destinationAddress, gatewayAddress, maskAddress, iface, 1);
		}

		// send init request
		sendRipRequest();

		System.out.println(routeTable);

		// start thread
		// send unsolicited response
		new Thread(() -> {
			// wait one second
			System.out.println("send out rip requests");
			try
			{ Thread.sleep(10000); }
			catch (InterruptedException e)
			{ return; }

			sendUnsolicitedRipResponse();
		}).start();

		// start thread
		// timout
		new Thread(() -> {
			// wait one second
			try
			{ Thread.sleep(500); }
			catch (InterruptedException e)
			{ return; }

			for(RouteEntry entry : this.routeTable.getEntries()) {
				if(entry.getGatewayAddress() != 0) {
					if((entry.getTimestamp() + 30000) <= System.currentTimeMillis()) {
						this.routeTable.remove(entry.getDestinationAddress(), entry.getMaskAddress());
					}
				}
			}
		}).start();
	}

	private void sendSolicitedRipResponse(int destIp, byte[] destMac, Iface outIface) {
		sendRip(RIPv2.COMMAND_RESPONSE, destIp, destMac, outIface);
	}

	private void sendUnsolicitedRipResponse() {
		sendRip(RIPv2.COMMAND_RESPONSE, -1, null, null);
	}

	private void sendRipRequest() {
		sendRip(RIPv2.COMMAND_REQUEST, -1, null, null);
	}


	private void sendRip(byte command, int destIp, byte[] destMac, Iface outIface) {


		// create headers
		Ethernet etherHeader = new Ethernet();
		etherHeader.setEtherType(Ethernet.TYPE_IPv4);

		if(destIp != -1) {
			etherHeader.setDestinationMACAddress(destMac);
		}
		else {
			etherHeader.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
		}

		IPv4 ipHeader = new IPv4();
		if(outIface != null) {
			ipHeader.setDestinationAddress(destIp);
		}
		else {
			ipHeader.setDestinationAddress("224.0.0.9");
		}
		ipHeader.setProtocol(IPv4.PROTOCOL_UDP);

		UDP udpHeader = new UDP();
		udpHeader.setDestinationPort(UDP.RIP_PORT);
		udpHeader.setSourcePort(UDP.RIP_PORT);

		// link
		etherHeader.setPayload(ipHeader);
		ipHeader.setPayload(udpHeader);
		

		if(outIface == null) {
			// send tables to all ports
			for(Iface iface :  this.getInterfaces().values()) {
				RIPv2 table = new RIPv2();
				table.setCommand(command);
				for(RouteEntry entry : this.routeTable.getEntries()) {
					RIPv2Entry tableEntry = new RIPv2Entry(entry.getDestinationAddress(), entry.getMaskAddress(), entry.getMetric());
					tableEntry.setNextHopAddress(iface.getIpAddress()); // TODO maybe
					table.addEntry(tableEntry);
				}
				udpHeader.setPayload(table);
				etherHeader.setSourceMACAddress(iface.getMacAddress().toString());
				this.sendPacket(etherHeader, iface);
			}
		}
		else {
			RIPv2 table = new RIPv2();
			for(RouteEntry entry : this.routeTable.getEntries()) {
				RIPv2Entry tableEntry = new RIPv2Entry(entry.getDestinationAddress(), entry.getMaskAddress(), entry.getMetric());
				tableEntry.setNextHopAddress(outIface.getIpAddress()); // TODO maybe
				table.addEntry(tableEntry);
			}
			udpHeader.setPayload(table);
			etherHeader.setSourceMACAddress(outIface.getMacAddress().toString());
			this.sendPacket(etherHeader, outIface);
		}
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
				// check if RIP
				if(isRIP(etherPacket)) {
					this.handleRipPacket(etherPacket, inIface);
				}
				else {
					this.handleIpPacket(etherPacket, inIface);
				}
				break;
			case Ethernet.TYPE_ARP:
				this.handleArpPacket(etherPacket, inIface);
				break;
		}

		/********************************************************************/
	}

	private boolean isRIP(Ethernet etherPacket) {
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		if (ipPacket.getProtocol() == IPv4.PROTOCOL_UDP
				&& ipPacket.getDestinationAddress() == IPv4.toIPv4Address("224.0.0.9")) {
			UDP udpPacket = (UDP) ipPacket.getPayload();
			if(udpPacket.getDestinationPort() == UDP.RIP_PORT) {
				return true;
			}
		}

		return false;
	}

	private void handleRipPacket(Ethernet etherPacket, Iface inIface) {
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		UDP udpPacket = (UDP) ipPacket.getPayload();
		RIPv2 table = (RIPv2) udpPacket.getPayload();

		if(table.getCommand() == RIPv2.COMMAND_REQUEST) {
			sendSolicitedRipResponse(ipPacket.getDestinationAddress(), etherPacket.getDestinationMACAddress(), inIface);
			return;
		}

		for(RIPv2Entry ripEntry : table.getEntries()) {
			int destinationAddress = ripEntry.getAddress();
			int gatewayAddress = ripEntry.getNextHopAddress();
			int maskAddress = ripEntry.getSubnetMask();
			RouteEntry routeEntry = this.routeTable.find(ripEntry.getAddress(), ripEntry.getSubnetMask());

			if(routeEntry == null) {
				this.routeTable.insert(destinationAddress, gatewayAddress, maskAddress, inIface, ripEntry.getMetric() + 1);
			}
			else if (routeEntry.getMetric() > ripEntry.getMetric()){
				this.routeTable.remove(routeEntry.getDestinationAddress(), routeEntry.getMaskAddress());
				this.routeTable.insert(destinationAddress, gatewayAddress, maskAddress, inIface, ripEntry.getMetric() + 1);
			}
			else {
				routeEntry.resetTimestamp(); // TODO done by gage
			}
		}
		System.out.println(this.routeTable);
	}


	private void handleArpPacket(Ethernet etherPacket, Iface inIface) {
		// Get ARP header
		ARP arpPacket = (ARP)etherPacket.getPayload();

		// get target ip protocol
		int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();

		System.out.println("Handle ARP packet");

		// if an ARP packet is an ARP request
		if(arpPacket.getOpCode() == ARP.OP_REQUEST) {
			System.out.println("Received ARP Request from: " + IPv4.fromIPv4Address(IPv4.toIPv4Address(arpPacket.getSenderProtocolAddress())));
			// if target ip is equal to interfaced packet was received
			System.out.println(IPv4.fromIPv4Address(targetIp) + " == " + IPv4.fromIPv4Address(inIface.getIpAddress()));

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
				System.out.println("Sent ARP Reply");
				this.sendPacket(etherHeader, inIface);
			}

		}
		// if received an arp reply
		else if(arpPacket.getOpCode() == ARP.OP_REPLY) {
			System.out.println("Received ARP Reply: " + IPv4.fromIPv4Address(IPv4.toIPv4Address(arpPacket.getSenderProtocolAddress())));
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
			sendArpRequest(ether, bestMatch.getInterface(), inIface, nextHop);
		}
		else{
			System.out.println("Found in arp cache: " + IPv4.fromIPv4Address(nextHop));
			ether.setDestinationMACAddress(arp_entry.getMac().toString());
			this.sendPacket(ether, inIface);
		}
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
			sendArpRequest(etherPacket, outIface, inIface, nextHop);
			return;
		}
		etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());

		System.out.println("Forwarding packet");
		this.sendPacket(etherPacket, outIface);
	}

	void sendArpRequest(Ethernet etherPacket, Iface outIface, Iface inIface, int nextHop) {
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();

		// if ip queue doesnt exist -> create queue and start timout
		if(!arpQueueMap.containsKey(nextHop)) {
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
			arpHeader.setSenderProtocolAddress(outIface.getIpAddress());
			arpHeader.setTargetHardwareAddress(MACAddress.valueOf(0).toBytes());
			arpHeader.setTargetProtocolAddress(nextHop);

			// link headers
			etherHeader.setPayload(arpHeader);
			arpQueueMap.put(nextHop, new ArpQueue(etherHeader, this, inIface));
			System.out.println("Create new queue");
		}

		// add packet to queue
		arpQueueMap.get(nextHop).insert(etherPacket);
		System.out.println("Add to queue");
	}
}
