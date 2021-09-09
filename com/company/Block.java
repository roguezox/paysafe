package com.company;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Block {
    String hash;
    String previousHash;
    String data;
    String timeStamp;
    byte[] publickey_snd;
    byte[] publickkey_rec;
    public Block(String data, String timestamp, String prevhash, byte[] publickeysender,byte[] publickey_receiver){
        this.data=data;
        this.previousHash=prevhash;
        this.timeStamp=timestamp;
        this.hash=blockhash();
        this.publickey_snd=publickeysender;
        this.publickkey_rec=publickey_receiver;
    }
    public String blockhash() {
        String initialstr= previousHash+data+timeStamp;

        MessageDigest digest = null;
        byte[] bytes = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
            bytes = digest.digest(initialstr.getBytes(UTF_8));
        } catch (NoSuchAlgorithmException ex) {
            System.out.print(Level.SEVERE+ ex.getMessage());
        }
        StringBuffer buffer = new StringBuffer();
        for (byte b : bytes) {
            buffer.append(String.format("%02x", b));
        }
        return buffer.toString();
    }

}
