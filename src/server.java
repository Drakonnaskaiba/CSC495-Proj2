import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;





class TCPServer
{
    
   public static void main(String argv[]) throws Exception
      {
          
        
         String clientSentence;
         String capitalizedSentence;
         ServerSocket welcomeSocket = new ServerSocket(6789);
         Key_Management keyman;
         String Alice_key;

          System.out.println("listening on port: 6789");
         while(true)
         {
             
            Socket connectionSocket = welcomeSocket.accept();
             System.out.println("Connection detected.");
            keyman = new Key_Management();
            
            
            BufferedReader inFromClient =
               new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));
            DataOutputStream outToClient = new DataOutputStream(connectionSocket.getOutputStream());
             System.out.println("Created buffered reader");
            Decoder d = Base64.getDecoder();
            
            
             String pbyte = inFromClient.readLine();
             byte[] Pb = d.decode(pbyte);
             String gbyte = inFromClient.readLine();
             byte[] Gb = d.decode(gbyte);
             
             BigInteger P = new BigInteger(Pb);
             BigInteger G = new BigInteger(Gb);
             byte[] public_key = keyman.generate_Public_Key(P, G);
             
             
            Alice_key = inFromClient.readLine();
            
            byte[] Alice_byte_key = d.decode(Alice_key);
             System.out.println(Alice_key);
             
            
          
            Encoder e = Base64.getEncoder();
            outToClient.writeBytes(new String(e.encode(public_key))+"\n");
            
             System.out.println("sent public key");
            
//             
            byte[] sharedsecret = keyman.compute_shared_key(Alice_byte_key, P, G);
            
            
            //System.out.println(new String(sharedsecret));
            for (int c=0;c<sharedsecret.length;c++){
                System.out.print(sharedsecret[c]);
            }
            
            
            
//            clientSentence = inFromClient.readLine();
//            
//            
//            
//            
//            System.out.println("Received: " + clientSentence);
//            capitalizedSentence = clientSentence.toUpperCase() + '\n';
//            outToClient.writeBytes(capitalizedSentence);
         }
      }
   
   
  
   
   
   
   
   
}

