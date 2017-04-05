
import java.io.*;
import java.net.*;
import java.util.Base64;

class TCPClient {

    public static void main(String argv[]) throws Exception {
        // Declare a key manager and set the Diffie-Hellman parameters.
        DHKeyManager keyman1 = new DHKeyManager(1024);
        keyman1.generateParameters();
        
        // method fields used to hold strings to be read and written.
        String sentence;
        String modifiedSentence;
        String[] tenthousandWordList;

        // Readers and Writers used to communicate across TCP/IP connection.
        BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));
        Socket clientSocket = new Socket("localhost", 6789);
        DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
        DataInputStream inFromServer = new DataInputStream(clientSocket.getInputStream());
        
        
        
        
        // Part 1:  Establish Shared Secret between Server and Client.
        // Key Agreement
        byte[] message = keyman1.returnMyPublicKey();
        // Transmit our public key to the server
        outToServer.writeUTF(new String(Base64.getEncoder().encode(message)));
        // Receive public key from the server.
        String key = inFromServer.readUTF();
        byte[] theirKey = Base64.getDecoder().decode(key);
        keyman1.setTheirPublicKey(theirKey);
        // Compute the shared secret using code found in the KeyManager class.
        byte[] outputA = keyman1.computeSharedSecret();

        // Print out the shared secret as Base64.
        System.out.println("DH shared secret: " + new String(Base64.getEncoder().encode(outputA)));
        
        
        // Created a delay in order to test each phase separately
        String delay = inFromUser.readLine();
        
        // Part 2:  Transmit string "Network Security" using the shared key
        // Using DES.
        // Since DES uses only 8 bytes for its keysize, we will use the last 8 bytes of the shared secret as a symmetric key.
        byte[] DESKey = new byte[8];
        int start = outputA.length - 8;
            for (int c = start; c < outputA.length;c++){
                DESKey[c - start] = outputA[c];
            }
        // Create new DES enctryption object and use it for the session.
        DESEncryption encrypter = new DESEncryption(DESKey);
        sentence = "Network Security";
        // Send "Network Security" to the server using DES encryption.
        outToServer.writeUTF(encrypter.encryptDES(sentence));
        // Read and decrypt response from server and print the results.
        modifiedSentence = encrypter.decryptDES(inFromServer.readUTF());
        System.out.println("FROM SERVER: " + modifiedSentence);
        
        
        
        // Created a delay in order to test each phase separately
        delay = inFromUser.readLine();
        
        // Part 3:  Compare and contrast the time taken by each protocol of Confidentiality
        // Using the 10,000 word list.
        File file = new File("10000words.txt");
        BufferedReader reader = new BufferedReader(new FileReader(file));
        tenthousandWordList = new String[9914];
        for (int c=0;c < tenthousandWordList.length;c++){
            tenthousandWordList[c] = reader.readLine();
        }
        // Encrypt each word and send to the server.
        System.out.println("Starting 10,000 word list encryptions.");
        // Pass the word list to the testDESENCRYPTION method so this method can be timed.
        String[] encrypted = testDESEncrytion(tenthousandWordList, encrypter);
        // Transmit the encrypted word list to the server for decrypting.
        for (int c = 0; c < 9914;c++){
            outToServer.writeUTF(encrypted[c]);
        }
        
        
        
        
        // Created a delay in order to test each phase separately
        delay = inFromUser.readLine();
        
        // Part 4:  Ensure message integrity is preserved.
        // Send message "Network Security" using H-MAC
        sentence = "Network Security";
        // Transmit hash of string to the server without DES encryption.
        outToServer.writeUTF(encrypter.sha256Encode(sentence));
        // Receive response from server.
        modifiedSentence = encrypter.decryptDES(inFromServer.readUTF());
        // Print out the response.
        System.out.println(modifiedSentence);
        
        // Using 10,000 word list.
        String[] hashed = testSHA256Hashing(tenthousandWordList, encrypter);
        // Send the hashed word list to the server.
        for (int c = 0; c < 9914;c++){
            outToServer.writeUTF(hashed[c]);
        }
        // Print out response from server.
        modifiedSentence = encrypter.decryptDES(inFromServer.readUTF());
        System.out.println(modifiedSentence);
        
        
        
        
        
        
        // Part 5:  Conduct a brute-force key attack against DES and RSA
        // No code, stategy is explained in the report.
        
        // Close the socket and end the program.
        clientSocket.close();
    }
    
    // separate static class used for speed testing RSA encrytion using the Profiler.
    public static String[] testDESEncrytion(String[] wordList, DESEncryption encrypter){
        String[] encrypted = new String[wordList.length];
        for (int c = 0;c < wordList.length;c++){
            encrypted[c] = encrypter.encryptDES(wordList[c]);
        }
        return encrypted;
    }
    // separate static class used for speed testing SHA256 hashing using the Profiler.
    public static String[] testSHA256Hashing(String[] wordList, DESEncryption encrypter){
        String[] hashed = new String[wordList.length];
        for (int c = 0;c < wordList.length;c++){
            hashed[c] = encrypter.sha256Encode(wordList[c]);
        }
        return hashed;
    }
}
