import javax.crypto.Cipher;
import java.net.*;
import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

public class Server {

    public static void main(String[] args) throws IOException {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            ServerSocket serverSocket = new ServerSocket(1234);
            System.out.println("Server is listening on port 1234");

            Socket socket = serverSocket.accept();
            System.out.println("Client connected");

            ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());

            outputStream.writeObject(keyPair.getPublic());
            outputStream.flush();

            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

            PublicKey clientPublicKey = (PublicKey) inputStream.readObject();
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);

            BufferedReader consoleInput = new BufferedReader(new InputStreamReader(System.in));

            String inputLine;
            while ((inputLine = consoleInput.readLine()) != null) {
                byte[] encryptedMessage = encryptCipher.doFinal(inputLine.getBytes());
                outputStream.writeObject(encryptedMessage);
                outputStream.flush();

                byte[] encryptedResponse = (byte[]) inputStream.readObject();
                String decryptedResponse = new String(decryptCipher.doFinal(encryptedResponse));
                System.out.println("Client: " + decryptedResponse);
            }

            inputStream.close();
            outputStream.close();
            socket.close();
            serverSocket.close();
        }catch (Exception e) {
            e.printStackTrace();
        }
    }
}