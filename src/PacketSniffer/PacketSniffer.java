package PacketSniffer;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.Packet;
import jpcap.*;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.List;

import javax.swing.table.TableModel;
import javax.swing.table.DefaultTableModel;
import javax.xml.bind.DatatypeConverter;

public class PacketSniffer extends javax.swing.JFrame {
    private static final Logger logger = Logger.getLogger(PacketSniffer.class.getName());

    public PacketSniffer() {
        initComponents();
        captureButton.setEnabled(false);
        stopButton.setEnabled(false);
        saveButton.setEnabled(false);
        filter_options.setEnabled(false);
        loadSavedPackets(); // Load saved packets when starting
    }

    //Globals
    public static NetworkInterface[] NETWORK_INTERFACES;
    public static JpcapCaptor CAP;
    jpcap_thread THREAD;
    public static int INDEX = 0;
    public static int flag = 0;
    public static int COUNTER = 0;
    boolean CaptureState = false;
    public static int No = 0;

    JpcapWriter writer = null;
    List<Packet> packetList = new ArrayList<>();

    private void loadSavedPackets() {
        List<String> savedPackets = CookieManager.loadPackets();
        for (String packet : savedPackets) {
            String[] parts = packet.split(" ", 6);
            if (parts.length >= 5) {
                Object[] row = {Integer.parseInt(parts[0]), parts[1], parts[2], parts[3], parts[4]};
                ((javax.swing.table.DefaultTableModel) jTable1.getModel()).addRow(row);
                No = Math.max(No, Integer.parseInt(parts[0]) + 1);
            }
        }
    }

    //HEX-View two functions.
    public static String toHexadecimal(String text) throws UnsupportedEncodingException {
        byte[] myBytes = text.getBytes("UTF-8");

        return DatatypeConverter.printHexBinary(myBytes);
    }

    public static String customizeHexa(String text) {

        String out;
        out = text.replaceAll("(.{32})", "$1\n");
        return out.replaceAll("..(?!$)", "$0 ");
    }

    public void CapturePackets() {
        THREAD = new jpcap_thread() {
            public Object construct() {
                try {
                    if (CAP != null) {
                        CAP.close();
                    }
                    
                    // Open device with larger buffer and in promiscuous mode
                    CAP = JpcapCaptor.openDevice(NETWORK_INTERFACES[INDEX], 65535, true, 100);
                    if (CAP == null) {
                        throw new IOException("Failed to open network device");
                    }
                    
                    // Set non-blocking mode for continuous capture
                    CAP.setNonBlockingMode(true);
                    
                    String filter = filter_options.getSelectedItem().toString();
                    if (!"---".equals(filter)) {
                        CAP.setFilter(filter.toLowerCase(), true);
                    }

                    PacketContents packetHandler = new PacketContents();
                    
                    // Start capture loop
                    while (CaptureState) {
                        try {
                            Packet packet = CAP.getPacket();
                            if (packet != null) {
                                packetHandler.receivePacket(packet);
                                if (writer != null) {
                                    writer.writePacket(packet);
                                }
                            } else {
                                // Small sleep when no packets to prevent CPU overload
                                Thread.sleep(1);
                            }
                        } catch (InterruptedException ie) {
                            break;
                        } catch (Exception e) {
                            if (CaptureState) { // Only log if we're still supposed to be capturing
                                logger.log(Level.WARNING, "Error processing packet: " + e.getMessage(), e);
                            }
                        }
                    }
                    
                } catch (IOException e) {
                    logger.log(Level.SEVERE, "Failed to open network device: " + e.getMessage(), e);
                } finally {
                    if (CAP != null) {
                        CAP.close();
                    }
                    if (writer != null) {
                        writer.close();
                    }
                }
                return 0;
            }

            public void finished() {
                this.interrupt();
            }
        };
        THREAD.start();
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jMenuBar2 = new javax.swing.JMenuBar();
        jMenu2 = new javax.swing.JMenu();
        jMenu3 = new javax.swing.JMenu();
        jMenu4 = new javax.swing.JMenu();
        jMenuItem1 = new javax.swing.JMenuItem();
        jToolBar1 = new javax.swing.JToolBar();
        listButton = new java.awt.Button();
        jLabel1 = new javax.swing.JLabel();
        filter_options = new javax.swing.JComboBox<>();
        captureButton = new java.awt.Button();
        stopButton = new java.awt.Button();
        saveButton = new java.awt.Button();
        jScrollPane4 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable(){
            public boolean isCellEditable(int row, int column){
                return false;
            }
        };
        jScrollPane1 = new javax.swing.JScrollPane();
        jTextArea1 = new javax.swing.JTextArea();
        jScrollPane2 = new javax.swing.JScrollPane();
        jTextArea2 = new javax.swing.JTextArea();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jMenuBar1 = new javax.swing.JMenuBar();

        jMenu2.setText("File");
        jMenuBar2.add(jMenu2);

        jMenu3.setText("Edit");
        jMenuBar2.add(jMenu3);

        jMenu4.setText("jMenu4");

        jMenuItem1.setText("jMenuItem1");

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("OOADJ Packet Sniffer");
        setName("OOADJ Packet Sniffer"); // NOI18N

        jToolBar1.setRollover(true);

        listButton.setActionCommand("List Interfaces");
        listButton.setBackground(new java.awt.Color(0, 0, 102));
        listButton.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        listButton.setForeground(new java.awt.Color(255, 255, 255));
        listButton.setLabel("List Interfaces");
        listButton.setPreferredSize(new java.awt.Dimension(90, 26));
        listButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                listButtonActionPerformed(evt);
            }
        });
        jToolBar1.add(listButton);

        jLabel1.setText(" Filter");
        jToolBar1.add(jLabel1);

        filter_options.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "---", "TCP", "UDP", "ICMP" }));
        filter_options.setPreferredSize(new java.awt.Dimension(320, 24));
        filter_options.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                filter_optionsActionPerformed(evt);
            }
        });
        jToolBar1.add(filter_options);

        captureButton.setBackground(new java.awt.Color(0, 204, 0));
        captureButton.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        captureButton.setLabel("Capture");
        captureButton.setPreferredSize(new java.awt.Dimension(83, 24));
        captureButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                captureButtonActionPerformed(evt);
            }
        });
        jToolBar1.add(captureButton);

        stopButton.setBackground(new java.awt.Color(255, 0, 51));
        stopButton.setFont(new java.awt.Font("Dialog", 1, 12)); // NOI18N
        stopButton.setLabel("Stop");
        stopButton.setPreferredSize(new java.awt.Dimension(83, 24));
        stopButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                stopButtonActionPerformed(evt);
            }
        });
        jToolBar1.add(stopButton);

        saveButton.setLabel("Save");
        saveButton.setPreferredSize(new java.awt.Dimension(83, 24));
        saveButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveButtonActionPerformed(evt);
            }
        });
        jToolBar1.add(saveButton);

        jTable1.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Packet Number", "Length", "Source IP", "Destination IP", "Protocol"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Integer.class, java.lang.Object.class, java.lang.Object.class, java.lang.Object.class, java.lang.String.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });
        jTable1.setRowHeight(20);
        jTable1.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jTable1MouseClicked(evt);
            }
        });
        jScrollPane4.setViewportView(jTable1);

        jTextArea1.setEditable(false);
        jTextArea1.setColumns(20);
        jTextArea1.setRows(5);
        jScrollPane1.setViewportView(jTextArea1);

        jScrollPane2.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        jTextArea2.setEditable(false);
        jTextArea2.setColumns(20);
        jTextArea2.setRows(5);
        jScrollPane2.setViewportView(jTextArea2);

        jLabel2.setText("Packet info:");

        jLabel3.setText("Hex view:");
        setJMenuBar(jMenuBar1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane4)
            .addComponent(jToolBar1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addComponent(jScrollPane1)
            .addComponent(jScrollPane2)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel2)
                    .addComponent(jLabel3))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jToolBar1, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE, 312, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 9, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 140, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel3)
                .addGap(1, 1, 1)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 108, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jTable1MouseClicked(java.awt.event.MouseEvent evt) {
        Object obj = jTable1.getModel().getValueAt(jTable1.getSelectedRow(), 0);
        Object[] packetData = PacketContents.getPacketData((int)obj);
        
        if ("TCP".equals(packetData[4])) {
            jTextArea1.setText(String.format(
                "Packet No: %s\nSeq No: %s\nProtocol: %s\nSource IP: %s\nDist IP: %s\n" +
                "Length: %s\nSource Port: %s\nDist Port: %s\nAck: %s\nAck No: %s\n" +
                "Sequence No: %s\nHeader: %s\nData: %s",
                packetData[0], packetData[10], packetData[4], packetData[2], packetData[3],
                packetData[1], packetData[5], packetData[6], packetData[7], packetData[8],
                packetData[10], packetData[12], packetData[9]
            ));
        } else if ("UDP".equals(packetData[4])) {
            jTextArea1.setText(String.format(
                "Packet No: %s\nProtocol: %s\nSource IP: %s\nDist IP: %s\n" +
                "Length: %s\nSource Port: %s\nDist Port: %s\nOffset: %s\n" +
                "Header: %s\nData: %s",
                packetData[0], packetData[4], packetData[2], packetData[3],
                packetData[1], packetData[5], packetData[6], packetData[8],
                packetData[9], packetData[7]
            ));
        } else if ("ICMP".equals(packetData[4])) {
            jTextArea1.setText(String.format(
                "Packet No: %s\nProtocol: %s\nSource IP: %s\nDist IP: %s\n" +
                "Length: %s\nChecksum: %s\nHeader: %s\nOffset: %s\n" +
                "Originate TimeStamp: %s bits\nRecieve TimeStamp: %s bits\n" +
                "Transmit TimeStamp: %s bits\nData: %s",
                packetData[0], packetData[4], packetData[2], packetData[3],
                packetData[1], packetData[5], packetData[6], packetData[7],
                packetData[8], packetData[9], packetData[10], packetData[11]
            ));
        }

        try {
            jTextArea2.setText(customizeHexa(toHexadecimal(jTextArea1.getText())));
        } catch (UnsupportedEncodingException ex) {
            logger.log(Level.SEVERE, "Error converting text to hex", ex);
        }
    }

    private void captureButtonActionPerformed(java.awt.event.ActionEvent evt) {
        try {
            CaptureState = true;
            CapturePackets();
            saveButton.setEnabled(false);
            filter_options.setEnabled(false);
            listButton.setEnabled(false);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to start capture: " + e.getMessage(), e);
        }
    }

    private void stopButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_stopButtonActionPerformed
        CaptureState = false;
        if (writer != null) {
            writer.close();
            writer = null;
        }
        if (THREAD != null) {
            THREAD.finished();
        }
        saveButton.setEnabled(true);
        filter_options.setEnabled(true);
        listButton.setEnabled(true);
    }//GEN-LAST:event_stopButtonActionPerformed

    private void listButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_listButtonActionPerformed
        PacketSniffer.COUNTER = 0; // Reset counter before listing interfaces
        InterfacesWindow nw = new InterfacesWindow();
        nw.setLocationRelativeTo(null); // Center the window
    }//GEN-LAST:event_listButtonActionPerformed

    private void saveButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saveButtonActionPerformed

        THREAD = new jpcap_thread() {
            public Object construct() {
                TableModel m = jTable1.getModel();
                CookieManager.clearPackets();
                for(int i = 0; i < m.getRowCount(); i++) {
                    String packet = String.format("%s %s %s %s %s", 
                        m.getValueAt(i, 0).toString(),
                        m.getValueAt(i, 1).toString(),
                        m.getValueAt(i, 2).toString(),
                        m.getValueAt(i, 3).toString(),
                        m.getValueAt(i, 4).toString()
                    );
                    CookieManager.savePacket(packet);
                }
                return 0;
            }

            public void finished() {
                this.interrupt();
            }
        };
        THREAD.start();


    }//GEN-LAST:event_saveButtonActionPerformed

    private void filter_optionsActionPerformed(java.awt.event.ActionEvent evt) {
        String selectedFilter = filter_options.getSelectedItem().toString();
        DefaultTableModel model = (DefaultTableModel) jTable1.getModel();
        
        // Clear the current table
        model.setRowCount(0);
        
        // Get all packets
        List<Object[]> packets = PacketContents.getAllPackets();
        
        // If no filter is selected, show all packets
        if ("---".equals(selectedFilter)) {
            for (Object[] row : packets) {
                model.addRow(new Object[]{
                    row[0], row[1], row[2], row[3], row[4]
                });
            }
            return;
        }
        
        // Show only packets matching the selected protocol
        for (Object[] row : packets) {
            if (selectedFilter.equals(row[4])) {
                model.addRow(new Object[]{
                    row[0], row[1], row[2], row[3], row[4]
                });
            }
        }
    }//GEN-LAST:event_filter_optionsActionPerformed

    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            logger.log(Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            logger.log(Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            logger.log(Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            logger.log(Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new PacketSniffer().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    public static java.awt.Button captureButton;
    public static javax.swing.JComboBox<String> filter_options;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JMenu jMenu2;
    private javax.swing.JMenu jMenu3;
    private javax.swing.JMenu jMenu4;
    private javax.swing.JMenuBar jMenuBar1;
    private javax.swing.JMenuBar jMenuBar2;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane4;
    public static javax.swing.JTable jTable1;
    public static javax.swing.JTextArea jTextArea1;
    private javax.swing.JTextArea jTextArea2;
    private javax.swing.JToolBar jToolBar1;
    public static java.awt.Button listButton;
    public static java.awt.Button saveButton;
    public static java.awt.Button stopButton;
    // End of variables declaration//GEN-END:variables
}

