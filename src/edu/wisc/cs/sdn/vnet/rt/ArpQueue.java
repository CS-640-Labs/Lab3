package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;

import net.floodlightcontroller.packet.ARP;

import java.util.LinkedList;
import java.util.Queue;

/**
 * A MAC learning table.
 * @author Aaron Gember-Jacobson
 */
public class ArpQueue implements Runnable
{
	private Queue<Ethernet> packets;
	private Thread timeoutThread;
	private Ethernet arpRequest;
	private Router router;
	private Iface inIface;

	public ArpQueue(Ethernet arpRequest, Router router, Iface inIface)
	{
		this.arpRequest = arpRequest;
		this.router = router;
		this.packets = new LinkedList<>();
		this.inIface = inIface;

		timeoutThread = new Thread(this);
		timeoutThread.start();

	}

	public void insert(Ethernet etherPacket) {
		System.out.println("inserted: " + IPv4.fromIPv4Address(((IPv4) etherPacket.getPayload()).getDestinationAddress()) + " with length=" + this.packets.size());
		this.packets.add(etherPacket);

	}

	public void dequeuePackets(byte[] destinationMAC, Iface outIface) {
		timeoutThread.interrupt();
		while(packets.size() > 0) {
			Ethernet etherPacket = packets.poll();
			System.out.println("Send packet: "
					+ IPv4.fromIPv4Address(((IPv4) etherPacket.getPayload()).getSourceAddress())
					+ " to "
					+ IPv4.fromIPv4Address(((IPv4) etherPacket.getPayload()).getDestinationAddress()));

			etherPacket.setDestinationMACAddress(destinationMAC);
			router.sendPacket(etherPacket, outIface);
		}
	}

	private void broadcastPackets() {
		System.out.println("Broadcast arp packet for: "
				+ IPv4.fromIPv4Address(IPv4.toIPv4Address(((ARP) arpRequest.getPayload()).getTargetProtocolAddress())));
		for(Iface outIface : router.getInterfaces().values()) {
			router.sendPacket(arpRequest, outIface);
		}
	}



	public void dropPackets() {
		System.out.println("Dropping packets");
		while(packets.size() > 0) {
			Ethernet etherPacket = packets.poll();
			router.generateICMP((IPv4) etherPacket.getPayload(), this.inIface,3,1);
			System.out.println("Dropped packet");
		}
	}


	/**
	 * Every second: timeout MAC table entries.
	 */
	public void run() {
		// timout after 3 total sends (including the init)
		int timesSent = 0;
		while (timesSent < 3) {
			// send packet
			broadcastPackets();
			timesSent ++;

			// wait one second
			try
			{ Thread.sleep(1000); }
			catch (InterruptedException e)
			{ return; }
		}

		// if here the no reply was received -> drop queued packets
		dropPackets();
	}
}
