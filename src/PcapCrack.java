/*
 *                             PcapCrack 1.0                        
 *             Copyright © 2017 Ben Goldsworthy (rumperuu)        
 *                                                                      
 * A program to attempt to brute-force the key used to encrypt a file
 * in an intercepted network packet. 
 *                                                                           
 * This file is part of PcapCrack.                                         
 *                                                                            
 * PcapCrack is free software: you can redistribute it and/or modify        
 * it under the terms of the GNU General Public License as published by       
 * the Free Software Foundation, either version 3 of the License, or          
 * (at your option) any later version.                                        
 *                                                                            
 * PcapCrack is distributed in the hope that it will be useful,             
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              
 * GNU General Public License for more details.                               
 *                                                                            
 * You should have received a copy of the GNU General Public License          
 * along with PcapCrack.  If not, see <http://www.gnu.org/licenses/>.       
 */

/**
 ** This class runs the brute-forcer, assigning a number of threads
 ** equal to the given computer's number of cores to the task.
 **/
 
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.tcpip.Tcp;

/**
 **   @author  Ben Goldsworthy (rumperuu) <me+pcapcrack@bengoldsworthy.net>
 **   @version 1.0
 **/
public class PcapCrack {
   private final static String PAYLOAD_STRING = "##ENCFILE##([^#]+)####";
   private final static Pattern pattern = Pattern.compile(PAYLOAD_STRING);
   
   private static ArrayList<String> passwords = new ArrayList<String>();
   private static BufferedReader br = null;
   
   /**
    **   Main function. Receives and validates arguments, then actives
    **   cracker threads.
    **   
    **   @param args The arguments passed to the program at the
    **   command-line.
    **/
   public static void main(String[] args) {
      // Verifies the correct number of arguments were passed to the
      // program.
      if (args.length == 2) {
         // Opens the specified `.pcap` file.
         final StringBuilder errbuf = new StringBuilder();
         final Pcap pcap = Pcap.openOffline(args[0], errbuf);
         if (pcap == null) {
            System.err.println(errbuf);
            return;
         }
         
         // Reads in the specified dictionary file.
         try {            
            String line;
            br = new BufferedReader(new FileReader(args[1]));
            while ((line = br.readLine()) != null) {
               passwords.add(line);
            }
         } catch (FileNotFoundException e) {
            System.out.println("File <"+args[1]+"> not found.");
            System.exit(1);
         } catch (IOException e) {
            e.printStackTrace();
            System.exit(1);
         } 
         
         // Reads each packet in the `.pcap` file.
         pcap.loop(100, new JPacketHandler<StringBuilder>() {
            final Tcp tcp = new Tcp();
            String payload = "";
            Matcher matcher;
            
            public void nextPacket(JPacket packet, StringBuilder errbuf) {
               if (packet.hasHeader(Tcp.ID)) {
                  packet.getHeader(tcp);

                  // When/if the payload packet is found, activates a
                  // number of cracker threads equal to the number of
                  // cores present.
                  payload = new String(tcp.getPayload()).split("\r")[0];
                  if (Pattern.compile(PAYLOAD_STRING).matcher(payload).matches()) {
                     payload = payload.replaceAll(PAYLOAD_STRING, "$1");
                     System.out.println("Encrypted file: " + payload + "\n");
                     
                     int cores = Runtime.getRuntime().availableProcessors();
                     ExecutorService executor = Executors.newFixedThreadPool(cores);
                     
                     for (int i = 1; i <= 18; i++) {
                        executor.execute(new Cracker(i, payload, passwords));
                     }
                     
                     executor.shutdown();
                     
                     // Waits until all threads have terminated.
                     while (!executor.isTerminated()) { }
                     
                     System.out.println("Finished all threads");
                  }
               }
            }
         }, errbuf);
      } else {
         System.out.println("Invalid number of argument(s). Program should be run with the following argument(s):");
         System.out.println("\tpa.jar <.pcap file> <dictionary file>");
         System.exit(1);
      }
   }
}
