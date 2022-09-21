package com.techartworks.encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EncryptionUtils {

    private static KeyPair generateKey(final int size) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(size);
        return generator.generateKeyPair();
    }

    private static String encryptPassword(final String secretPassword)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException {
        byte[] publicKeyBytes = Files.readAllBytes(new File("public.pem").toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] secretMessageBytes = secretPassword.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);
        final String encryptedPassword = Base64.getEncoder().encodeToString(encryptedMessageBytes);
        System.out.println(encryptedPassword);
        return encryptedPassword;
    }

    private static String decryptPassword(final String encryptedPassword)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException {
        byte[] privateKeyBytes = Files.readAllBytes(new File("private.pem").toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        final RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMessageBytes = decryptCipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
        return new String(decryptedMessageBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException {

        //Initial code to create the Key.
        //generateKeys();

        final String encryptPassword = encryptPassword("TestVirginSecret");
        System.out.println(decryptPassword(encryptPassword));


    }

    private static void generateKeys() throws NoSuchAlgorithmException {
        final var generatedKeys = EncryptionUtils.generateKey(2048);
        final var publicKey = generatedKeys.getPublic();
        try (FileOutputStream fos = new FileOutputStream("public.pem")) {
            fos.write(publicKey.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        final var privateKey = generatedKeys.getPrivate();
        try (FileOutputStream fos = new FileOutputStream("private.pem")) {
            fos.write(privateKey.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
