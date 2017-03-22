import java.io.*;
import java.net.*;
 
class TCPServer
{
   public static void main(String argv[]) throws Exception
      {
          RSAKeyManager keyman = new RSAKeyManager(2048);
          
         String clientSentence;
         String capitalizedSentence;
         ServerSocket welcomeSocket = new ServerSocket(6789);
 
         while(true)
         {
            Socket connectionSocket = welcomeSocket.accept();
             System.out.println("Incoming connection");
           // BufferedReader inFromClient =
               //new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));
            DataInputStream inFromClient = new DataInputStream(connectionSocket.getInputStream()) ;  
            DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());
            
            int msglength = inFromClient.readInt();
             System.out.println("Got message length");
            byte[] theirKey = new byte[msglength];
                System.out.println("created byte array   : " + theirKey.length);
            inFromClient.readFully(theirKey, 0, theirKey.length);
            
             System.out.println("Received Client's Key");
            
            keyman.setTheirPublicKey(theirKey);
            
            byte[] my_key = keyman.returnMyPublicKey();
            outToClient.write(my_key.length);
            outToClient.write(my_key);
            
            int keylength = inFromClient.readInt();
            byte[] e_shared_secret = new byte[keylength];
            inFromClient.readFully(e_shared_secret, 0, e_shared_secret.length);
            
            byte[] shared_secret = keyman.decrypte_with_RSA(e_shared_secret);
            
            
            System.out.println(new String(shared_secret));
            
            
            
            
            
            clientSentence = inFromClient.readLine();
            System.out.println("Received: " + clientSentence);
            capitalizedSentence = clientSentence.toUpperCase() + '\n';
            outToClient.writeBytes(capitalizedSentence);
         }
      }
}