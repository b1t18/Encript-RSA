package rsa;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class RSA {
    public static void main(String[] args) throws Exception {

        // 1. Entreda del mensaje para encriptar
        Scanner input = new Scanner(System.in);
        System.out.println("Ingresa un mensaje para encriptar: ");
        String mensaje = input.nextLine();

        // 2. Generamos la clave pública y privada (RSA)
        KeyPair clavesRSA = generarClavesRSA();
        PublicKey clavePublica = clavesRSA.getPublic();
        PrivateKey clavePrivada = clavesRSA.getPrivate();

        // 3. Implementamos cifrado
        byte[] byteCrifado = encriptar(mensaje, clavePublica);

        // 4. Imprimir datos
        System.out.println("Texto original es: " + mensaje);
        System.out.println("Texto bytes encriptado es: " + new String(byteCrifado));

        // 5. Implementar decifrado
        byte[] byteDecrifado = desencriptar(byteCrifado, clavePrivada);

        // 6. Imprimir datos
        System.out.println("Texto decifrado es: " + new String(byteDecrifado));
    }

    public static KeyPair generarClavesRSA() throws Exception
    {
        KeyPairGenerator gestorClave = KeyPairGenerator.getInstance("RSA");
        gestorClave.initialize(2048);

        return gestorClave.generateKeyPair();
    }

    public static byte[] encriptar(String mensaje, PublicKey clavePublica) throws Exception
    {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, clavePublica);

        return cipher.doFinal(mensaje.getBytes());
    }

    public static byte[] desencriptar(byte[] encriptadoCipher, PrivateKey clavePrivada) throws Exception
    {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, clavePrivada);

        return cipher.doFinal(encriptadoCipher);
    }
}