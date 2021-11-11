package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;

import net.floodlightcontroller.packet.ARP;

import java.util.Arrays;
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
		this.packets.add(etherPacket);

	}

	public void dequeuePackets(byte[] destinationMAC, Iface outIface) {
		timeoutThread.interrupt();
		while(packets.size() > 0) {
			Ethernet etherPacket = packets.poll();
			etherPacket.setDestinationMACAddress(destinationMAC);
			router.sendPacket(etherPacket, outIface);
		}
	}

	private void broadcastPackets() {
		for(Iface outIface : router.getInterfaces().values()) {
			router.sendPacket(arpRequest, outIface);
		}
	}



	public void dropPackets() {
		while(packets.size() > 0) {
			Ethernet etherPacket = packets.poll();
			router.generateICMP((IPv4) etherPacket.getPayload(), this.inIface,3,1);
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
