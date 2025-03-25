package PacketSniffer;

import java.io.*;
import java.util.*;

public class CookieManager {
    private static final String COOKIE_FILE = "packet_cookies.txt";
    private static List<String> samplePackets;

    static {
        // Initialize with sample packet data for presentation
        samplePackets = Arrays.asList(
            "1 74 192.168.1.100 216.58.200.78 TCP HTTP_GET_Request",
            "2 66 216.58.200.78 192.168.1.100 TCP HTTP_200_OK",
            "3 1500 192.168.1.100 239.255.255.250 UDP SSDP_Discovery",
            "4 120 192.168.1.1 192.168.1.100 ICMP Echo_Request",
            "5 120 192.168.1.100 192.168.1.1 ICMP Echo_Reply",
            "6 1280 192.168.1.100 173.194.222.103 TCP TLS_Handshake",
            "7 548 192.168.1.100 208.67.222.222 UDP DNS_Query",
            "8 890 192.168.1.100 104.244.42.1 TCP HTTPS_POST",
            "9 445 104.244.42.1 192.168.1.100 TCP HTTPS_Response",
            "10 662 192.168.1.100 172.217.167.46 TCP HTTP_POST"
        );
    }

    public static void savePacket(String packet) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(COOKIE_FILE, true))) {
            writer.write(packet + "\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static List<String> loadPackets() {
        List<String> packets = new ArrayList<>();
        try {
            File file = new File(COOKIE_FILE);
            if (!file.exists()) {
                // For presentation, return sample packets if no saved packets exist
                return new ArrayList<>(samplePackets);
            }
            
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line;
            while ((line = reader.readLine()) != null) {
                packets.add(line);
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
            // Return sample packets if there's an error
            return new ArrayList<>(samplePackets);
        }
        return packets;
    }

    public static void clearPackets() {
        try {
            new FileWriter(COOKIE_FILE).close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}