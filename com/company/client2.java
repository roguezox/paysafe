package com.company;

import org.apache.commons.net.ntp.NTPUDPClient;
import org.apache.commons.net.ntp.TimeInfo;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

public class client2 {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keygen= KeyPairGenerator.getInstance("DSA");
        keygen.initialize(2048);
        KeyPair kypr= keygen.generateKeyPair();

        String Timeserver= "time.google.com";
        NTPUDPClient timeClient = new NTPUDPClient();
        InetAddress inetAddress = InetAddress.getByName(Timeserver);

        TimeInfo timeInfo = timeClient.getTime(inetAddress);
        long returnTime = timeInfo.getReturnTime();
        Date time = new Date(returnTime);
        System.out.print(time);
    }
}
