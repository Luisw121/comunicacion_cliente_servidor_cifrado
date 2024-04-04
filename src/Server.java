import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;

public class Server {

    public static void main(String[] args) throws IOException {
        try {

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair serverKeyPair = keyGen.generateKeyPair();

            ServerSocket serverSocket = new ServerSocket(1234);
            System.out.println("Server is listening on port 1234");
            Socket socket = serverSocket.accept();
            System.out.println("Client connected");

            ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());
            outputStream.writeObject(serverKeyPair.getPublic());
            outputStream.flush();

            PublicKey clientPublicKey = (PublicKey) inputStream.readObject();

            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, serverKeyPair.getPrivate());
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);

            Thread readThread = new Thread(() -> {
                try {

                    while (true) {

                        byte[] encryptedMessage = (byte[]) inputStream.readObject();
                        String decryptedMessage = new String(decryptCipher.doFinal(encryptedMessage));
                        System.out.println("Client: " + decryptedMessage);

                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });

            readThread.start();

            BufferedReader consoleInput = new BufferedReader(new InputStreamReader(System.in));
            String inputLine;
            while ((inputLine = consoleInput.readLine()) != null) {

                byte[] encryptedMessage = encryptCipher.doFinal(inputLine.getBytes());

                outputStream.writeObject(encryptedMessage);
                outputStream.flush();
            }

            inputStream.close();
            outputStream.close();
            socket.close();
            serverSocket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
