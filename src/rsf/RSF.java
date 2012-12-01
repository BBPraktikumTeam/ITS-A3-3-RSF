package rsf;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

public class RSF {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		File prvFile = null;
		File pubFile = null;
		File inFile = null;
		File outFile = null;
		if (args.length == 4) {
			prvFile = new File(args[0]);
			pubFile = new File(args[1]);
			inFile = new File(args[2]);
			outFile = new File(args[3]);
			rsf(prvFile, pubFile, inFile, outFile);
		} else {
			System.out
					.println("Bitte Parameter in der Reihenfolge: <privater Schluessel des Empfängers> <oeffentlicher Schluessel des Senders> <Queldatei> <Zieldatei> angeben.");
			System.exit(1);
		}
	}

	private static void rsf(File prvFile, File pubFile, File inFile,
			File outFile) {
		
		
		//Keys erzeugen
				RSAPrivateKey privateKey = (RSAPrivateKey) getRSAKey(prvFile,
						"RSA", true);
				RSAPublicKey publicKey = (RSAPublicKey) getRSAKey(pubFile, "RSA", false);
				byte[] decDataBytes = decryptAndVerify(inFile,"AES",privateKey,publicKey);
				try {
					FileOutputStream fos = new FileOutputStream(outFile);
					fos.write(decDataBytes);
				} catch (Exception e) {
					error(e);
				}
				
				
	}
	
	private static byte[] encryptData(File inFile, File outFile, SecretKeySpec aesKey) {
		byte[] buf = null;
		try {
			DataInputStream in = new DataInputStream(new FileInputStream(inFile));

			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			error(e);
		}

	//	cipher.doFinal(input);

		return buf;
	}
	
	private static byte[] decryptAndVerify(File encFile, String algo, RSAPrivateKey privkey, RSAPublicKey pubKey) {
		SecretKey ks = null;
		byte[] decDataBytes = null;
		try {//Keylänge auslesen
		FileInputStream fis = new FileInputStream(encFile);
		byte[] intLength = new byte[4];
		fis.read(intLength);
		ByteBuffer bb = ByteBuffer.wrap(intLength);
		int keyLength = bb.getInt();
		System.out.println(keyLength);
		//KeyAuslesen
		byte[] encKeyBytes = new byte[keyLength];
		fis.read(encKeyBytes);
		//Key Entschlüsseln
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privkey);
		byte[] decKeyBytes = cipher.doFinal(encKeyBytes);
			
		ks = new SecretKeySpec(decKeyBytes, "AES");
		System.out.println(ks.getAlgorithm());
	
		System.out.println("Geheimen Schlüssel ausgelesen: " + new String(ks.getEncoded()));
		
		//Signaturlänge auslesen
		fis.read(intLength);
		bb = ByteBuffer.wrap(intLength);
		int signLength = bb.getInt();
		System.out.println("Signaturlänge: " + signLength);
		//Signatur auslesen
		byte[] signBytes = new byte[signLength];
		fis.read(signBytes);
		if (!isAESKeyOriginal(signBytes,ks,pubKey)) throw new Exception("AES Key is kompromised");
		//Init cipher
		cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE,ks);
		
		//EncrData auslesen
//		
//		byte[] buffer = new byte[8];
//		int len = 0;
//		while ((len = fis.read(buffer)) > 0) {
//			cipher.update(buffer);
//		}
		
 		int bytes = fis.available();
 		byte[] buf = new byte[bytes];
 		System.out.println("MessageLength: " + bytes);
		fis.read(buf);
		decDataBytes = cipher.doFinal(buf);
		
		fis.close();
		} catch (Exception e) {
			error(e);
		}
		
		return decDataBytes;
	}

	private static boolean isAESKeyOriginal(byte[] signBytes, SecretKey aesKey, RSAPublicKey pubKey) {
		boolean isOriginal = false;
		Signature sig = null;
		try {
			
			
			sig = Signature.getInstance("SHA1withRSA");
			sig.initVerify(pubKey);
			sig.update(aesKey.getEncoded());
			isOriginal = sig.verify(signBytes);
			
			System.out.println("Verfied: " + isOriginal);
			
		} catch (Exception e) {
			error(e);
		}
		
		
		return isOriginal;
	}
	
	private static RSAKey getRSAKey(File keyFile, String algo, boolean isPrivate) {
		String name = "";
		RSAKey key = null;
		try {
			FileInputStream fis = new FileInputStream(keyFile);
			// Namenslänge auslesen
			byte[] intLength = new byte[4];
			fis.read(intLength);
			ByteBuffer bb = ByteBuffer.wrap(intLength);
			int nameLength = bb.getInt();
			System.out.println(nameLength);
			// Namen auslesen
			byte[] nameBytes = new byte[nameLength];
			fis.read(nameBytes);
			name = new String(nameBytes);
			System.out.println(name);
			// Key Länge auslesen.
			fis.read(intLength);
			bb = ByteBuffer.wrap(intLength);
			int keyLength = bb.getInt();
			System.out.println(keyLength);
			// KeyAuslesen
			byte[] keyBytes = new byte[keyLength];
			fis.read(keyBytes);
			// PrivateKey Object erstellen
			KeyFactory keyFactory = KeyFactory.getInstance(algo);
			if (isPrivate) {
				KeySpec ks = new PKCS8EncodedKeySpec(keyBytes);
				key = (RSAPrivateKey) keyFactory.generatePrivate(ks);
				System.out.println(((RSAPrivateKey) key).getFormat());
			} else {
				X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(
						keyBytes);
				key = (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
				System.out.println(((RSAPublicKey) key).getFormat());
			}
			String prvOrPub = "";
			if (isPrivate) {
				prvOrPub = "Private";
			} else {
				prvOrPub = "Public";
			}
			System.out.println(prvOrPub + "Key erfolgreich eingelesen: " + key);
			fis.close();
		} catch (Exception e) {
			error(e);
		}
		return key;
	}

	private static void error(Exception e) {
		if (e instanceof IOException || e instanceof FileNotFoundException) {
			System.out.println("File not found");
		} else if (e instanceof NoSuchAlgorithmException) {
			System.out.println("Algorithm not found");
		} else if (e instanceof InvalidKeySpecException) {
			System.out.println("Invalid key");
		} else if (e instanceof NoSuchProviderException) {
			System.out.println("Provider not found");
		} else if (e instanceof SignatureException) {
			System.out.println("Fehler beim Signieren");
		} else if (e instanceof BadPaddingException
				|| e instanceof IllegalBlockSizeException) {
			System.out.println("Fehler bei Verschlüsselung");
		} else if (e instanceof NoSuchPaddingException) {
			System.out.println("Padding not found");
		} else {
			System.out.println("Exception: " + e.getMessage());
		}
		e.printStackTrace();
	}
}
