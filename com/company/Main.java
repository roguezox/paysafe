package com.company;

import org.apache.commons.io.FileUtils;
import org.apache.commons.net.ntp.NTPUDPClient;
import org.apache.commons.net.ntp.TimeInfo;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.util.Date;

public class Main {
    public static final String ALGORITHM = "RSA";

    public static String dir=System.getProperty("user.home");
    public static void main(String[] args) throws Exception {
        byte[] pk,sk;
        // if statement checks if the key pairs have been created before and saved in the encrypted file
        if (Files.exists(Paths.get(dir+"/Music/crypto/encryptedfile-pub.des"))){
            String password = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
            pk=decryptfile(dir+"/Music/crypto/encryptedfile-pub.des",dir+"/Music/crypto/publickey.txt","2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",dir+"/Music/crypto/saltpub.enc",dir+"/Music/crypto/ivpub.enc");
            sk=decryptfile(dir+"/Music/crypto/encryptedfile-sec.des",dir+"/Music/crypto/secretkey.txt","2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",dir+"/Music/crypto/saltsec.enc",dir+"/Music/crypto/ivsec.enc");

        }
        // well if the program is running for the first time then it creates the pair of public and private key and saves them in the file
        else {
            KeyPairGenerator keygen= KeyPairGenerator.getInstance("RSA");
            keygen.initialize(2048);
            KeyPair kypr= keygen.generateKeyPair();

            PublicKey publicKeyk= kypr.getPublic();
            PrivateKey secretkey= kypr.getPrivate();
            pk = publicKeyk.getEncoded();
            sk = secretkey.getEncoded();
            // the below encrypt key file function encrypts the files in which the keys are saved.
            String confirmation_pub= encryptfile(dir + "/Music/crypto/pub.txt",dir+"/Music/crypto/encryptedfile-pub.des",pk,"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",dir+"/Music/crypto/saltpub.enc",dir+"/Music/crypto/ivpub.enc");
            String confirmation_sec= encryptfile(dir + "/Music/crypto/sec.txt",dir+"/Music/crypto/encryptedfile-sec.des",sk,"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",dir+"/Music/crypto/saltsec.enc",dir+"/Music/crypto/ivsec.enc");
            System.out.print("public key: "+confirmation_pub+"\n");
            System.out.print("secret key:"+confirmation_sec+"\n");

        }


        Block[] blocks=new Block[5];
        blocks[1]=createblock("hello",time(),"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", pk, sk);
        System.out.print(blocks[1].hash+"\n"+blocks[1]);




    }
    public static byte[] encrypt(byte[] publicKey, byte[] inputData)
            throws Exception {

        PublicKey key = KeyFactory.getInstance(ALGORITHM)
                .generatePublic(new X509EncodedKeySpec(publicKey));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encryptedBytes = cipher.doFinal(inputData);

        return encryptedBytes;
    }
    public static byte[] decrypt(byte[] privateKey, byte[] inputData)
            throws Exception {

        PrivateKey key = KeyFactory.getInstance(ALGORITHM)
                .generatePrivate(new PKCS8EncodedKeySpec(privateKey));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE,key);

        byte[] decryptedBytes = cipher.doFinal(inputData);

        return decryptedBytes;
    }
    public static Block  createblock(String data, String time, String prevhash,byte[] publickeysender,byte[] publickey_receiver){
          Block block= new Block(data,time,prevhash,publickeysender,publickey_receiver);
          return block;
    }
    public static String time() throws IOException {
        String Timeserver= "time.google.com";
        NTPUDPClient timeClient = new NTPUDPClient();
        InetAddress inetAddress = InetAddress.getByName(Timeserver);

        TimeInfo timeInfo = timeClient.getTime(inetAddress);
        long returnTime = timeInfo.getReturnTime();
        Date time = new Date(returnTime);

        return time.toString();
    }
    public static byte[] key(String filename) throws IOException {
        FileInputStream fos = new FileInputStream(filename);
        DataInputStream outStream = new DataInputStream(new BufferedInputStream(fos));
        byte[] key= outStream.readAllBytes();
        outStream.close();
        return key;

    }
    // this is the function that is used to decrypt the encrypted key file , well you need not know how this function works just see the parameters and understand what it returns
    public static byte[] decryptfile(String filename,String outfile,String password,String saltfile,String ivfile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {


        // reading the salt
        // user should have secure mechanism to transfer the
        // salt, iv and password to the recipient
        FileInputStream saltFis = new FileInputStream(saltfile);
        byte[] salt = new byte[8];
        saltFis.read(salt);
        saltFis.close();

        // reading the iv
        FileInputStream ivFis = new FileInputStream(ivfile);
        byte[] iv = new byte[16];
        ivFis.read(iv);
        ivFis.close();

        SecretKeyFactory factory = SecretKeyFactory
                .getInstance("PBKDF2WithHmacSHA1");
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536,
                256);
        SecretKey tmp = factory.generateSecret(keySpec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

        // file decryption
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
        FileInputStream fis = new FileInputStream(filename);
        FileOutputStream fos = new FileOutputStream(outfile);
        byte[] in = new byte[64];
        int read;
        while ((read = fis.read(in)) != -1) {
            byte[] output = cipher.update(in, 0, read);
            if (output != null)
                fos.write(output);
        }

        byte[] output = cipher.doFinal();
        if (output != null)
            fos.write(output);
        fis.close();
        fos.flush();
        fos.close();
        System.out.println("File Decrypted.");
        byte[] key= FileUtils.readFileToByteArray(new File(outfile));
        FileUtils.delete(new File(outfile));
        return key;

    }
    // this function is used to encrypt the key files
    public static String encryptfile(String filename,String outfile,byte[] data,String password,String saltfile,String ivfile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException {
        FileUtils.writeByteArrayToFile(new File(filename),data);
        FileOutputStream outFile = new FileOutputStream(outfile);
        FileInputStream inFile = new FileInputStream(filename);
        byte[] salt = new byte[8];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salt);
        FileOutputStream saltOutFile = new FileOutputStream(saltfile);
        saltOutFile.write(salt);
        saltOutFile.close();

        SecretKeyFactory factory = SecretKeyFactory
                .getInstance("PBKDF2WithHmacSHA1");
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536,
                256);
        SecretKey secretKey = factory.generateSecret(keySpec);
        SecretKey secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

        //
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        AlgorithmParameters params = cipher.getParameters();

        // iv adds randomness to the text and just makes the mechanism more
        // secure
        // used while initializing the cipher
        // file to store the iv
        FileOutputStream ivOutFile = new FileOutputStream(ivfile);
        byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        ivOutFile.write(iv);
        ivOutFile.close();

        //file encryption
        byte[] input = new byte[64];
        int bytesRead;

        while ((bytesRead = inFile.read(input)) != -1) {
            byte[] output = cipher.update(input, 0, bytesRead);
            if (output != null)
                outFile.write(output);
        }

        byte[] output = cipher.doFinal();
        if (output != null)
            outFile.write(output);

        inFile.close();
        outFile.flush();
        outFile.close();
        FileUtils.delete(new File(filename));
        return "file encrypted";
    }



}
