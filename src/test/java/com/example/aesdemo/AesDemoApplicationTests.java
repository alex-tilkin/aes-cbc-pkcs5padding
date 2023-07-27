package com.example.aesdemo;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class AesDemoApplicationTests {

    @Test
    void genereate_key_test() throws NoSuchAlgorithmException {
        System.out.println(Base64.getEncoder().encodeToString(AesDemoApplication.generateKey(256).getEncoded()));
    }
    @Test
    void encrypt_decrypt_identical_input_equals_plain_text() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException,
            NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String secretKeyStr = "cWrkCbX1JKCiWYFDx9DsHKqdn38QK5o3";
        SecretKey secretKey = AesDemoApplication.convertStringToSecretKeyto(secretKeyStr); // Convert the string to secret key
        IvParameterSpec ivParameterSpec = AesDemoApplication.generateIv(); // Generate Initialization Vector
        String encodedIv = Base64.getEncoder().encodeToString(ivParameterSpec.getIV());
        String input = "This is a test text";
        String algorithm = "AES/CBC/PKCS5Padding";

        String cipherText = AesDemoApplication.encrypt(algorithm, input, secretKey, ivParameterSpec);
        String plainText = AesDemoApplication.decrypt(algorithm, cipherText, secretKey, ivParameterSpec);
        System.out.println("Input: " + input + "; IV: " + encodedIv + "; Cipher text: " + cipherText + "; Plaint text: " + plainText);

        assertEquals(input, plainText);
    }

    @Test
    void encrypt_decrypt_extract_iv_and_generate_fromstring_inout_equals_plain_text() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException,
            NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String secretKeyStr = "cWrkCbX1JKCiWYFDx9DsHKqdn38QK5o3";
        SecretKey secretKey = AesDemoApplication.convertStringToSecretKeyto(secretKeyStr); // Convert the string to secret key
        IvParameterSpec ivParameterSpec = AesDemoApplication.generateIv(); // Generate Initialization Vector
        String encodedIv = Base64.getEncoder().encodeToString(ivParameterSpec.getIV());

        IvParameterSpec ivParameterSpecFromIv = new IvParameterSpec(Base64.getDecoder().decode(encodedIv));
        String input = "This is a test text";
        String algorithm = "AES/CBC/PKCS5Padding";

        String cipherText = AesDemoApplication.encrypt(algorithm, input, secretKey, ivParameterSpec);
        System.out.println(cipherText);
        String plainText = AesDemoApplication.decrypt(algorithm, cipherText, secretKey, ivParameterSpecFromIv);
        System.out.println("Input: " + input + "; IV: " + encodedIv + "; Cipher text: " + cipherText + "; Plain text: " + plainText);

        assertEquals(input, plainText);
    }
}
