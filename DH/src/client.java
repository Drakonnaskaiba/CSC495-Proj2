
import java.io.*;
import java.net.*;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

class TCPClient {

    public static void main(String argv[]) throws Exception {
        // Declare a key manager and set the Diffie-Hellman parameters.
        DHKeyManager keyman1 = new DHKeyManager(1024);
        keyman1.generateParameters();
        
        // method fields used to hold strings to be read and written.
        String sentence;
        String modifiedSentence;
        String[] tenthousandWordList;
        
        // read from the word list.
        File file = new File("10000words.txt");
        BufferedReader reader = new BufferedReader(new FileReader(file));
        tenthousandWordList = new String[9914];
        for (int c=0;c < tenthousandWordList.length;c++){
            tenthousandWordList[c] = reader.readLine();
        }
        
        // Readers and Writers used to communicate across TCP/IP connection.
        BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));
        Socket clientSocket = new Socket("localhost", 6789);
        DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
        DataInputStream inFromServer = new DataInputStream(clientSocket.getInputStream());
        
        // Key Agreement
        byte[] message = keyman1.returnMyPublicKey();
        outToServer.writeUTF(new String(Base64.getEncoder().encode(message)));
        String key = inFromServer.readUTF();
        byte[] theirKey = Base64.getDecoder().decode(key);
        keyman1.setTheirPublicKey(theirKey);
        byte[] outputA = keyman1.computeSharedSecret();

        // Use last 8 bytes of shared secret as the DES key.
        byte[] DESKey = new byte[8];
        int start = outputA.length - 8;
            for (int c = start; c < outputA.length;c++){
                DESKey[c - start] = outputA[c];
            }
            
        // Create new DES enctryption object and use it for the session.
        DESEncryption encrypter = new DESEncryption(DESKey);
        sentence = inFromUser.readLine();
        outToServer.writeUTF(encrypter.encryptDES(sentence));
        modifiedSentence = encrypter.decryptDES(inFromServer.readUTF());
        System.out.println("FROM SERVER: " + modifiedSentence);
        
        System.out.println("Starting 10,000 word list encryptions.");
        String[] encrypted = testDESEncrytion(tenthousandWordList, encrypter);
        for (int c = 0; c < 9914;c++){
            outToServer.writeUTF(encrypted[c]);
        }
        
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
}
