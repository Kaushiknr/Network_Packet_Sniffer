package PacketSniffer;

import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import javax.swing.table.DefaultTableModel;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;
import java.util.ArrayList;
import java.util.List;
import jpcap.packet.ICMPPacket;
import javax.swing.SwingUtilities;

public class PacketContents implements PacketReceiver {

    private static final List<Object[]> rowList = new ArrayList<>();
    private static final int BUFFER_SIZE = 1024;

    // Helper methods to access packet data
    public static Object[] getPacketData(int index) {
        return rowList.get(index);
    }
    
    public static int getPacketCount() {
        return rowList.size();
    }
    
    public static List<Object[]> getAllPackets() {
        return new ArrayList<>(rowList);
    }

    @Override
    public void receivePacket(Packet packet) {
        if (packet == null) return;
        
        try {
            if (packet instanceof TCPPacket) {
                handleTCPPacket((TCPPacket) packet);
            } else if (packet instanceof UDPPacket) {
                handleUDPPacket((UDPPacket) packet);
            } else if (packet instanceof ICMPPacket) {
                handleICMPPacket((ICMPPacket) packet);
            }
        } catch (Exception e) {
            System.err.println("Error processing packet: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private synchronized void handleTCPPacket(TCPPacket tcp) {
        final Object[] row = {PacketSniffer.No, tcp.length, tcp.src_ip.getHostAddress(), tcp.dst_ip.getHostAddress(), "TCP"};
        
        byte[] data = tcp.data != null ? tcp.data : new byte[0];
        byte[] header = tcp.header != null ? tcp.header : new byte[0];
        
        // Limit data size to prevent memory issues
        if (data.length > BUFFER_SIZE) {
            byte[] truncated = new byte[BUFFER_SIZE];
            System.arraycopy(data, 0, truncated, 0, BUFFER_SIZE);
            data = truncated;
        }
        
        rowList.add(new Object[]{
            PacketSniffer.No, 
            tcp.length, 
            tcp.src_ip.getHostAddress(), 
            tcp.dst_ip.getHostAddress(), 
            "TCP", 
            tcp.src_port,
            tcp.dst_port,
            tcp.ack,
            tcp.ack_num,
            new String(data),
            tcp.sequence,
            tcp.offset,
            new String(header)
        });

        updateUI(row);
    }

    private synchronized void handleUDPPacket(UDPPacket udp) {
        final Object[] row = {PacketSniffer.No, udp.length, udp.src_ip.getHostAddress(), udp.dst_ip.getHostAddress(), "UDP"};
        
        byte[] data = udp.data != null ? udp.data : new byte[0];
        byte[] header = udp.header != null ? udp.header : new byte[0];
        
        if (data.length > BUFFER_SIZE) {
            byte[] truncated = new byte[BUFFER_SIZE];
            System.arraycopy(data, 0, truncated, 0, BUFFER_SIZE);
            data = truncated;
        }
        
        rowList.add(new Object[]{
            PacketSniffer.No,
            udp.length,
            udp.src_ip.getHostAddress(),
            udp.dst_ip.getHostAddress(),
            "UDP",
            udp.src_port,
            udp.dst_port,
            new String(data),
            udp.offset,
            new String(header)
        });

        updateUI(row);
    }

    private synchronized void handleICMPPacket(ICMPPacket icmp) {
        final Object[] row = {PacketSniffer.No, icmp.length, icmp.src_ip.getHostAddress(), icmp.dst_ip.getHostAddress(), "ICMP"};
        
        byte[] data = icmp.data != null ? icmp.data : new byte[0];
        byte[] header = icmp.header != null ? icmp.header : new byte[0];
        
        if (data.length > BUFFER_SIZE) {
            byte[] truncated = new byte[BUFFER_SIZE];
            System.arraycopy(data, 0, truncated, 0, BUFFER_SIZE);
            data = truncated;
        }
        
        rowList.add(new Object[]{
            PacketSniffer.No,
            icmp.length,
            icmp.src_ip.getHostAddress(),
            icmp.dst_ip.getHostAddress(),
            "ICMP",
            icmp.checksum,
            new String(header),
            icmp.offset,
            icmp.orig_timestamp,
            icmp.recv_timestamp,
            icmp.trans_timestamp,
            new String(data)
        });

        updateUI(row);
    }

    private void updateUI(final Object[] row) {
        SwingUtilities.invokeLater(() -> {
            try {
                DefaultTableModel model = (DefaultTableModel) PacketSniffer.jTable1.getModel();
                model.addRow(row);
                PacketSniffer.No++;
            } catch (Exception e) {
                System.err.println("Error updating UI: " + e.getMessage());
            }
        });
    }

    public static List<Object[]> getRowList() {
        return new ArrayList<>(rowList);
    }
}
