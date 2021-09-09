package com.company;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;

import static java.nio.charset.StandardCharsets.UTF_8;
// this class is the block variable to and will be used frequently to create blocks for the blockchain
public class Block {
    String hash;
    String previousHash;
    String data;
    String timeStamp;
    byte[] publickey_snd;
    byte[] publickkey_rec;
    public Block(String data, String timestamp, String prevhash, byte[] publickeysender,byte[] publickey_receiver){
        // data is the information of who pays what to whom
        this.data=data;
        // this is the hash of the previous block
        this.previousHash=prevhash;
        // time of the payment
        this.timeStamp=timestamp;
        // hash of the current block and this blockhash() function is used to generate the block hash
        this.hash=blockhash();
        //public key of the sender
        this.publickey_snd=publickeysender;
        // public key of the receiver
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
