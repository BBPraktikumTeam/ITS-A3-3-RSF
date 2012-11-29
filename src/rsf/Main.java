package rsf;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class Main {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		String name;
		File privateKeyFile, publicKeyFile, decryptetFile, encryptetFile;
		// TODO Auto-generated method stub
		if (args.length != 4) {
			// java RSF FMeier.prv KMueller.pub Brief.ssf Brief.doc
			System.out
					.println("usage: java RSF <privateKeyFile> <publicKeyFile> <encryptetFile> <decryptedFile>");
			System.exit(0);
		}

		privateKeyFile = new File(args[0]);
		publicKeyFile = new File(args[1]);
		decryptetFile = new File(args[2]);
		encryptetFile = new File(args[3]);
		try {
			FileInputStream fis = new FileInputStream(privateKeyFile);
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
			//KeyAuslesen
			byte[] privKeyBytes = new byte[keyLength];
			fis.read(privKeyBytes);
			// PrivateKey Object erstellen
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			KeySpec ks = new PKCS8EncodedKeySpec(privKeyBytes);
			RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(ks);
			System.out.println(privKey.getFormat());
		} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.out.println("File not found");
			e.printStackTrace();
		}

	}

}
