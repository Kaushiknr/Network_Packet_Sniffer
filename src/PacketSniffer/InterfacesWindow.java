package PacketSniffer;


import java.awt.event.KeyEvent;
import javax.swing.*;
import jpcap.*;
import java.io.IOException;

public class InterfacesWindow extends javax.swing.JFrame {

    public InterfacesWindow() {
        initComponents();
        ListNetworkInterfaces();
        textField1.requestFocus();
        setVisible(true);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
    }

    public void ListNetworkInterfaces() {
        PacketSniffer.NETWORK_INTERFACES = JpcapCaptor.getDeviceList();
        jTextArea1.setText("");
        for (int i = 0; i < PacketSniffer.NETWORK_INTERFACES.length; i++) {
            jTextArea1.append(
                    "\n\n-----------------------------------------------------------------------Interface (" + i
                    + ") -----------------------------------------------------------------------");
            jTextArea1.append("\nInterface Number:   " + i);
            jTextArea1.append("\nDescription:              "
                    + PacketSniffer.NETWORK_INTERFACES[i].name + "("
                    + PacketSniffer.NETWORK_INTERFACES[i].description + ")");
            jTextArea1.append("\nDatalink Name:         "
                    + PacketSniffer.NETWORK_INTERFACES[i].datalink_name + "("
                    + PacketSniffer.NETWORK_INTERFACES[i].datalink_description + ")");
            jTextArea1.append("\nMac Address:            ");

            byte[] R = PacketSniffer.NETWORK_INTERFACES[i].mac_address;
            if (R != null) {
                StringBuilder macAddress = new StringBuilder();
                for (int A = 0; A < R.length; A++) {
                    macAddress.append(String.format("%02x", R[A] & 0xff));
                    if (A < R.length - 1) {
                        macAddress.append(":");
                    }
                }
                jTextArea1.append(macAddress.toString().toUpperCase());
            } else {
                jTextArea1.append("Not Available");
            }

            NetworkInterfaceAddress[] INT = PacketSniffer.NETWORK_INTERFACES[i].addresses;
            if (INT != null && INT.length > 0) {
                jTextArea1.append("\nIP Address:                " + INT[0].address);
                jTextArea1.append("\nSubnet Mask:            " + INT[0].subnet);
                jTextArea1.append("\nBroadcast Address: " + INT[0].broadcast);
            }

            PacketSniffer.COUNTER++;
        }
    }

    public void ChooseInterface() {
        int TEMP = Integer.parseInt(textField1.getText());

        if (TEMP > -1 && TEMP < PacketSniffer.COUNTER) {
            PacketSniffer.INDEX = TEMP;
            
            try {
                if (PacketSniffer.CAP != null) {
                    PacketSniffer.CAP.close();
                }
                
                // Initialize the device
                PacketSniffer.CAP = JpcapCaptor.openDevice(
                    PacketSniffer.NETWORK_INTERFACES[PacketSniffer.INDEX], 
                    65535, 
                    true, 
                    100
                );
                
                if (PacketSniffer.CAP != null) {
                    PacketSniffer.captureButton.setEnabled(true);
                    PacketSniffer.filter_options.setEnabled(true);
                    PacketSniffer.stopButton.setEnabled(true);
                    PacketSniffer.saveButton.setEnabled(true);
                } else {
                    JOptionPane.showMessageDialog(this, 
                        "Failed to open network interface", 
                        "Error", 
                        JOptionPane.ERROR_MESSAGE);
                    return;
                }
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, 
                    "Error opening interface: " + e.getMessage(), 
                    "Error", 
                    JOptionPane.ERROR_MESSAGE);
                return;
            }
        } else {
            JOptionPane.showMessageDialog(null, 
                "Outside the RANGE. # interfaces = 0-" + (PacketSniffer.COUNTER - 1) + ".");
            InterfacesWindow nw = new InterfacesWindow();
            return;
        }

        textField1.setText("");
        setVisible(false);
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        jTextArea1 = new javax.swing.JTextArea();
        jButton1 = new javax.swing.JButton();
        textField1 = new java.awt.TextField();
        jLabel1 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Interfaces List");
        setName("Interfaces list"); // NOI18N

        jTextArea1.setEditable(false);
        jTextArea1.setColumns(20);
        jTextArea1.setRows(5);
        jScrollPane1.setViewportView(jTextArea1);

        jButton1.setText("Select");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        textField1.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                textField1KeyPressed(evt);
            }
        });

        jLabel1.setText("Please select the interface number!");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(0, 249, Short.MAX_VALUE)
                        .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 224, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(textField1, javax.swing.GroupLayout.PREFERRED_SIZE, 70, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(47, 47, 47)
                        .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 75, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(jScrollPane1))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 352, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(textField1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jButton1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 33, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        // TODO add your handling code here:
        ChooseInterface();
        setVisible(false);
    }//GEN-LAST:event_jButton1ActionPerformed

    private void textField1KeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_textField1KeyPressed
        // TODO add your handling code here:
        if (evt.getExtendedKeyCode() == KeyEvent.VK_ENTER) {
            ChooseInterface();
            setVisible(false);
        }
    }//GEN-LAST:event_textField1KeyPressed

    public static void main(String args[]) {

        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(InterfacesWindow.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(InterfacesWindow.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(InterfacesWindow.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(InterfacesWindow.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new InterfacesWindow().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextArea jTextArea1;
    private java.awt.TextField textField1;
    // End of variables declaration//GEN-END:variables
}

