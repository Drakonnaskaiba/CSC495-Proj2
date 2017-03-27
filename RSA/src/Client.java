
import java.io.*;
import java.net.*;
import java.util.Base64;

class TCPClient {

    public static void main(String argv[]) throws Exception {
        // Declare a key manager and set the RSA parameters.
        RSAKeyManager keyman = new RSAKeyManager(1024);

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
        byte[] message = keyman.returnMyPublicKey();
        outToServer.writeUTF(new String(Base64.getEncoder().encode(message)));
        String key = inFromServer.readUTF();
        byte[] theirKey = Base64.getDecoder().decode(key);
        keyman.setTheirPublicKey(theirKey);

        // Generate and Encrypt a secret key.
        byte[] shared_secret = keyman.gen_DES_key();
        byte[] e_shared_secret = keyman.encrypt_with_RSA(shared_secret);
        outToServer.writeUTF(new String(Base64.getEncoder().encode(e_shared_secret)));

        System.out.println(new String(Base64.getEncoder().encode(shared_secret)));

        // Continue with RSA encryption/decryption.
        sentence = inFromUser.readLine();
        outToServer.writeUTF(new String(Base64.getEncoder().encode(keyman.encrypt_with_RSA(sentence.getBytes()))));
        String sent = inFromServer.readUTF();
        byte[] mess = Base64.getDecoder().decode(sent);
        modifiedSentence = new String(keyman.decrypte_with_RSA(mess));
        System.out.println("FROM SERVER: " + modifiedSentence);
        
        String[] encrypted = testRSAEncrytion(tenthousandWordList, keyman);
        for (int c=0;c < 9914;c++){
            outToServer.writeUTF(encrypted[c]);
        }
        
        clientSocket.close();
    }
    
    // separate static class used for speed testing RSA encrytion using the Profiler.
    public static String[] testRSAEncrytion(String[] wordList, RSAKeyManager keyman){
        String[] encrypted = new String[wordList.length];
        for (int c = 0;c < wordList.length;c++){
            
            encrypted[c] = new String(Base64.getEncoder().encode(keyman.encrypt_with_RSA(wordList[c].getBytes())));
        }
        return encrypted;
    }
}
