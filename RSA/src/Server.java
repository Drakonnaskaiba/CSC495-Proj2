import java.io.*;
import java.net.*;
import java.util.Base64;
 
class TCPServer
{
   public static void main(String argv[]) throws Exception
      {
          RSAKeyManager keyman = new RSAKeyManager(1024);
          
         String clientSentence;
         String capitalizedSentence;
         ServerSocket welcomeSocket = new ServerSocket(6789);
 
         while(true)
         {
             System.out.println("Waiting on incoming connection:");
            Socket connectionSocket = welcomeSocket.accept();
             System.out.println("Incoming connection received");
           // BufferedReader inFromClient =
               //new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));
            DataInputStream inFromClient = new DataInputStream(connectionSocket.getInputStream()) ;  
            DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());
            
            int msglength = inFromClient.readInt();
            byte[] theirKey = new byte[msglength];
            
            inFromClient.readFully(theirKey, 0, theirKey.length);
            
             System.out.println("Received Client's Key");
            
            keyman.setTheirPublicKey(theirKey);
             System.out.println("My Key:  " + new String(Base64.getEncoder().encode(keyman.returnMyPublicKey())));
             System.out.println("Their Key: " + new String(Base64.getEncoder().encode(keyman.returnTheirPublicKey().getEncoded())));
            
            byte[] my_key = keyman.returnMyPublicKey();
            outToClient.writeInt(my_key.length);
            outToClient.write(my_key);
            
            int keylength = inFromClient.readInt();
            byte[] e_shared_secret = new byte[keylength];
            inFromClient.readFully(e_shared_secret, 0, e_shared_secret.length);
            
            byte[] shared_secret = keyman.decrypte_with_RSA(e_shared_secret);
            
            
            System.out.println(new String(Base64.getEncoder().encode(shared_secret)));
            
            
            
            
            
            clientSentence = inFromClient.readLine();
            System.out.println("Received: " + clientSentence);
            capitalizedSentence = clientSentence.toUpperCase() + '\n';
            outToClient.writeBytes(capitalizedSentence);
         }
      }
}