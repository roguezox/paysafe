package com.company;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;

import static java.nio.charset.StandardCharsets.UTF_8;
// this just a test class to test the new code before adding it to main code
public class test {
    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket=new ServerSocket(8080);
        Socket socket= serverSocket.accept();
        DataInputStream dis=new DataInputStream(socket.getInputStream());
        String  str=(String)dis.readUTF();
        System.out.println("message= "+str);
        serverSocket.close();
    }
}
