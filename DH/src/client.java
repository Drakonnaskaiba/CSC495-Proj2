
import java.io.*;
import java.net.*;
import java.util.Base64;

class TCPClient {

    public static void main(String argv[]) throws Exception {
        DHKeyManager keyman1 = new DHKeyManager(1024);
        keyman1.generateParameters();
        String sentence;
        String modifiedSentence;
        BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));
        Socket clientSocket = new Socket("localhost", 6789);
        DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
        DataInputStream inFromServer = new DataInputStream(clientSocket.getInputStream());
        //BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        byte[] message = keyman1.returnMyPublicKey();
        outToServer.writeInt(message.length);
        outToServer.write(message);
        int length = inFromServer.readInt();
        byte[] theirKey = new byte[length];
        inFromServer.readFully(theirKey, 0, theirKey.length);
        keyman1.setTheirPublicKey(theirKey);
        byte[] outputA = keyman1.computeSharedSecret();
        String encoded = new String(Base64.getEncoder().encode(outputA));
        System.out.println("Computed Shared Secret: ");
        System.out.println(encoded);
        //sentence = inFromUser.readLine();
        //outToServer.writeBytes(sentence + '\n');
        //modifiedSentence = inFromServer.readLine();
        //System.out.println("FROM SERVER: " + modifiedSentence);
        clientSocket.close();
    }
}
