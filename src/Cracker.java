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
 ** This class represents a password-cracking thread utilising a given
 ** method for generating possible passwords.
 **/

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.regex.*;

import javax.crypto.*;
import javax.crypto.spec.*;

/**
 **   @author  Ben Goldsworthy (rumperuu) <me+pcapcrack@bengoldsworthy.net>
 **   @version 1.0
 **/
public class Cracker implements Runnable {
   private static final String ivVal = "1234567891011121";
   private static final char[] leet = {'a', '4', 'e', '3', 'i', '1', 'o', '0', 'l', '|', 't' , '7'};
   private static byte[] file;
   private static boolean found = false;
   
   private ArrayList<String> passwords;
   private int mode;
   MessageDigest digest;
   Cipher cipher;
   IvParameterSpec iv;
   
   /**
    **   Constructor.
    **   
    **   @param mode The method of password generation the thread will
    **   utilise.
    **   @param file The encoded file to crack, encoded in Base64.
    **   @param dict The `ArrayList` of words from the chosen dictionary.
    **/
   public Cracker(int mode, String file, ArrayList<String> dict){
      this.mode = mode;
      this.file = Base64.getDecoder().decode(file);
      
      // Initialises the dictionary to the passed file for all modes except
      // 0...
      if (this.mode > 2) {
         this.passwords = dict;
      // ...in which case, initialises the dictionary to the list of the
      // 10,000 most common passwords included with the .jar.
      } else {
         ArrayList<String> commonPasswords = new ArrayList<String>();
         try {        
            InputStream is = getClass().getResourceAsStream("/dat/10000-most-common-passwords.txt");
            InputStreamReader isr = new InputStreamReader(is);
            BufferedReader br = new BufferedReader(isr);    
            String line;
            while ((line = br.readLine()) != null) { commonPasswords.add(line); }
            this.passwords = commonPasswords;
         } catch (FileNotFoundException e) {
            System.out.println("File `10000-most-common-passwords.txt` not found in directory `.\\dat`.");
            System.exit(1);
         } catch (IOException e) {
            e.printStackTrace();
            System.exit(1);
         }
      }
      
      // If the cracker has an even mode, flips the order the password
      // list.
      if ((this.mode % 2)== 0) Collections.reverse(this.passwords);
      
      // Halves the cracker's list, to avoid duplicating effort with its
      // even twin.
      this.passwords = new ArrayList<String>(this.passwords.subList(0, this.passwords.size()/2));
      
      // Initialises as much of the crypto stuff as can be done at this 
      // stage.
      try {
         this.digest = MessageDigest.getInstance("SHA-256");
         this.cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
         this.iv = new IvParameterSpec(this.ivVal.getBytes());
      } catch (Exception e) {
         System.out.println(e);
      }
   }
   
   /**
    **   Runs the cracker process on the thread, and alerts on end.
    **/
   @Override
   public void run() {
      processCommand();
   }
   
   /**
    **   Tests every key generated using the given method for the thread.
    **   
    **   Mode 1: 10,000 most common passwords.
    **   Mode 3: Dictionary words.
    **   Mode 5: Dictionary words, with each letter capitalised in turn.
    **   Mode 7: Dictionary words, with ASCII symbols {!-/} appended.
    **   Mode 9: Dictionary words, with 'leetspeek' replacements.
    **   Mode 11: Dictionary words, capitalised.
    **   Mode 13: Dictionary words, with numbers {0-9999} appended 
    **              and prepended.
    **   Mode 15: Dictionary words, combined in pairs.
    **   Mode 17: Numbers {0-1,000,000}.
    **   
    **   Even-numbered modes are the previous mode, with a reversed 
    **   list. Thus, all modes terminate when halfway through.
    **/
   private void processCommand() {
      int j, k;
      
      int tenth = (int)Math.ceil(this.passwords.size()/10);
      int current = 0;
      int percentage = 0;
      // DEBUG: when using the test dictionary, avoids divide be zero
      // exceptions later on.
      if (this.passwords.size() < 10) tenth = 1;
      
      for (String password : this.passwords) {
         // If another cracker has found the correct password, stop.
         if (this.found) return;
         
         current++;
         switch (this.mode) {
         // Tests the unaltered dictionary word/common password.
         case 1:case 2:case 3:case 4:
            this.crack(password);
            break;
         // Capitalises each letter of each word in turn.
         case 5:case 6:
            for (j = 1; j < password.length() - 1; j++) {
               password = password.substring(0,j) + password.substring(j,j+1).toUpperCase() + password.substring(j+1);
               this.crack(password);
            }
            break;
         // Appends the symbols represented by ASCII values 33-47.
         case 7:case 8:
            for (j = 33; j < 48; j++) {
               password = password + (char)j;
               this.crack(password);
            }
            break;
         // Replaces each leet character in turn.
         case 9:case 10:
            for (j = 0; j < password.length() - 1; j++) {
               for (k = 0; k < this.leet.length; k+=2) {
                  if (password.charAt(j) == this.leet[k]) {
                     StringBuilder newPassword = new StringBuilder(password);
                     newPassword.setCharAt(j, this.leet[k+1]);
                     this.crack(newPassword.toString());
                  }
               }
            }
            break;
         // Capitalises the first letter of every word.
         case 11:case 12:
            password = password.substring(0,1).toUpperCase() + password.substring(1);
            this.crack(password);
            break;
         // Appends and prepends the numbers 1-9,999 to every word.
         case 13:case 14:
            for (j = 0; j < 9999 - 1; j++) {
               this.crack(password + j);
               this.crack(j + password);
            }
            break;
         // Appends and prepends the next word.
         case 15:case 16:
            for (j = 0; j < this.passwords.size() - 1; j++) {
               this.crack(password + this.passwords.get(j));
            }
            break;
         // Attempts the numbers 0-1,000,000.
         case 17:case 18:
            for (j = k = 0; (j <= 500000) && (k >= 500000); j++, k--) {
               this.crack(""+j);
               this.crack(""+k);
            }
            break;
         }
         
         // Displays the current progress.
         if ((current % tenth) == 0) {
            tenth += tenth;
            percentage += 10;
            System.out.println("Cracker "+mode+" at "+percentage+"%");
         }
      }
      
      // If there's been no return, none of the attempted passwords have
      // worked.
      System.out.println("Cracker " + this.mode + " end, no result.");
   }
   
   /**
    **   Tests a given password to see if it cracks the payload.
    **
    **   @param password The given password.
    **   @return Whether the file was cracked or not.
    **/
   private boolean crack(String password) {
      try {   
         // Sets up the cipher with the given password.
         byte[] keyVal = digest.digest(password.getBytes("UTF-8"));
         keyVal = Arrays.copyOfRange(keyVal, 0, keyVal.length/2);
         SecretKeySpec key = new SecretKeySpec(keyVal, "AES");
         cipher.init(Cipher.DECRYPT_MODE, key, iv);
         
         // Decrypts the file using the cipher.
         String decryptedFile = new String(cipher.doFinal(this.file));
         if (decryptedFile.startsWith("DECRYPTED:")) {
            // Must be outputted in a single command, or lines will be
            // broken up by output from other cracker threads.
            System.out.println("Cracker "+this.mode+" end, successful crack!\n==========\nDecrypted file: " + decryptedFile.split(":",2)[1] + "\nPassword: " + password + "\n==========\n");
            this.found = true;
            return true;
         }
      } catch (BadPaddingException e) {
         // If the password is incorrect, do nothing and move on to
         // returning "false".
      } catch (Exception e) {
         System.out.println(e);
      } finally {
         return false;
      }
   }
}
