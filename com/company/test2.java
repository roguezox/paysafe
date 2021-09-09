package com.company;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
// test class
public class test2 {
    public static void main(String[] args) throws IOException {
        Socket socket=new Socket("2401:4900:4638:148:a92b:f35f:8e89:c7f5",8080);
        DataOutputStream dout=new DataOutputStream(socket.getOutputStream());
        dout.writeUTF("Hello Server");
        dout.flush();
        dout.close();
        socket.close();
    }
}
