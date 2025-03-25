package PacketSniffer;

import java.net.*;
import java.io.*;
import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import jpcap.packet.*;

public class List_interfaces {
	JpcapCaptor captor;
	NetworkInterface[] list;
	String str, info;
	int x, choice;


	public static void main(String args[])
	{
		new List_interfaces();
	}
	
	public List_interfaces()
	{
		list = JpcapCaptor.getDeviceList();
		System.out.println("Available interfaces: ");
		
		for(x=0; x<list.length; x++)
		{
			System.out.println(x+" -> " + list[x].description);
		}
		System.out.println("--------------------------------");
		choice = Integer.parseInt(getInput("Choose interface(0, 1,..):"));
		System.out.println("Listening on interface ->" + list[choice].description);
		System.out.println("--------------------------------");
		
		try
		{
			captor=JpcapCaptor.openDevice(list[choice], 65536, true, 1000);
			
			//TCP and IP only
			//captor.setFilter("ip and tcp", true);
		}
		catch(IOException ioe)
		{
			ioe.printStackTrace();
		}
		
		//start listening
		while(true)
		{
			//System.out.println("H");
			Packet info = captor.getPacket();
			//System.out.println("ello");
			if(info!=null)
			{
					
					System.out.println(info);
			}
		}
	}

	public static String getInput(String q)
	{
		String input = "";
		System.out.print(q);
		BufferedReader bufferedreader = new BufferedReader(new InputStreamReader(System.in));
		try {
			input = bufferedreader.readLine();
		}
		catch(IOException ioexception)
		{
		}
		return input;
	}
}
