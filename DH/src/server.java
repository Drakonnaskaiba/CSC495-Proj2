
import java.io.*;
import java.net.*;
import java.util.Base64;

class TCPServer {

    public static void main(String argv[]) throws Exception {
        // Declare a key manager and set the Diffie-Hellman parameters.
        DHKeyManager keyman2 = new DHKeyManager(1024);

        // method fields used to hold strings to be read and written.
        String clientSentence;
        String capitalizedSentence;

        // Declare and initialize the server socket to listen on port 6789.
        ServerSocket welcomeSocket = new ServerSocket(6789);
        System.out.println("Listening for connection on port 6789");

        while (true) {
            Socket connectionSocket = welcomeSocket.accept();
            System.out.println("Connection received.");

            // Once a connection has been established, create the readers and writers used to communicate across TCP/IP connection.
            DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());
            DataInputStream inFromClient = new DataInputStream(connectionSocket.getInputStream());

            
            
            
            // Part 1:  Establish Shared Secret between Server and Client.
            // Key Agreement
            // Receive the public key from the client.
            String key = inFromClient.readUTF();
            byte[] theirKey = Base64.getDecoder().decode(key);
            keyman2.setTheirPublicKey(theirKey);
            // Set the parameter spec from the client's public key.
            keyman2.setDHParameterSpec();
            // Transmit our public key to the server
            byte[] myKey = keyman2.returnMyPublicKey();
            outToClient.writeUTF(new String(Base64.getEncoder().encode(myKey)));
            // Compute shared secret.
            byte[] outputB = keyman2.computeSharedSecret();
            // print out the shared secret which should match the printout in the client class.
            System.out.println("DH shared secret: " + new String(Base64.getEncoder().encode(outputB)));
            
            
            
            
            
            // Part 2:  Transmit string "Network Security" using the shared key
            // Using DES.
            // Since DES uses only 8 bytes for its keysize, we will use the last 8 bytes of the shared secret as a symmetric key.
            byte[] DESKey = new byte[8];
            int start = outputB.length - 8;
            for (int c = start; c < outputB.length; c++) {
                DESKey[c - start] = outputB[c];
            }
            // Create new DES enctryption object and use it for the session.
            DESEncryption encrypter = new DESEncryption(DESKey);
            // Read message from client and decrypt.
            clientSentence = encrypter.decryptDES(inFromClient.readUTF());
            System.out.println("Received from Client: " + clientSentence);
            // Capitalize the received message
            capitalizedSentence = clientSentence.toUpperCase();
            // Encrypt the capitalized message and send back to client.
            outToClient.writeUTF(encrypter.encryptDES(capitalizedSentence));
            
            
            
            // Part 3:  Compare and contrast the time taken by each protocol of Confidentiality
            // Read in the entire 10,000 word list from the client.          
            String[] encrypted = new String[9914];
            for (int c=0; c < 9914;c++){
                encrypted[c] = inFromClient.readUTF();
            }
            System.out.println("Start decryption of word list.");
            // Pass the word list to the testDESDecryption method so this method can be timed.
            String[] decrypted = testDESDecrytion(encrypted, encrypter);
            System.out.println("Decryption finished.");
            
            
            
            // Part 4:  Ensure message integrity is preserved.
            // Receive message "Network Security" using H-MAC
            String message = inFromClient.readUTF();
            // If the message integrity is confirmed, send back message to client.
            if (message.equals(encrypter.sha256Encode("Network Security"))){
                outToClient.writeUTF(encrypter.encryptDES("Message authenticated."));
            }
            else {
                outToClient.writeUTF(encrypter.encryptDES("Message NOT authenticated."));
            }
            
            // Using 10,000 word list.
            String[] hashed = new String[9914];
            for (int c=0; c < 9914;c++){
                hashed[c] = inFromClient.readUTF();
            }
            System.out.println("Start authentication of word list.");
            // Pass the word list to the testDESDecryption method so this method can be timed.
            if (testHMACAuthentication(hashed, decrypted, encrypter)){
                System.out.println("Word List was authenticated.");
                outToClient.writeUTF(encrypter.encryptDES("Word List was authenticated."));
            } else {
                System.out.println("Word List was NOT authenticated.");
                outToClient.writeUTF(encrypter.encryptDES("Word List was NOT authenticated."));
            }
            
            // Loop back for next connection.
        }
    }
    
    // separate static class used for speed testing RSA decrytion using the Profiler.
    public static String[] testDESDecrytion(String[] wordList, DESEncryption encrypter){
        String[] decrypted = new String[wordList.length];
        for (int c = 0;c < wordList.length;c++){
            decrypted[c] = encrypter.decryptDES(wordList[c]);
        }
        return decrypted;
    }
    
    public static boolean testHMACAuthentication(String[] hashedList, String[] wordList, DESEncryption encrypter){
        boolean success = true;
        for (int c = 0;c < hashedList.length;c++){
            if (hashedList[c].equals(encrypter.sha256Encode(wordList[c]))){
                
            } else {
                success = false;
            }
        }
        return success;
    }
}
