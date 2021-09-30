package ildar.android.rsaencryption.util;

import android.util.Base64;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;


public class RSAEncryption {

	/*Source : https://stackoverflow.com/questions/12471999/rsa-encryption-decryption-in-android/12474193 */

	String pubKey= "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmWsgewF82pdLQOiFyuOj\n" +
			"kbhLBn31sfGsxlWiYNpFCzkZx9R/tkQfw960HyDozmTWeQ4OMNrI3FSAFMvafAR6\n" +
			"QqBtQ7/H7Tdo1/KtJMzCgprvAQr5n4roAyH8CdlIC37AvYR/z6h9Ckvj2ZUzehHD\n" +
			"MhpwvLYZ+waOtuoxU0/1/7pjb6+rUpLvbsp/4Bm27g+FQw1skzDU7mCiHafHyjP/\n" +
			"/F2Mr9abYzArf9UTZMxtxJ9pQJZS20zKsB9jT4vDEjQ9FCwWgY4bno3IPcCnOUrr\n" +
			"3dzEgGpDauGWjEnWHtheQLzkKsBvuPCo1QxwnbMU1rWdBmvi4GitDpMhU9083p2o\n" +
			"kQIDAQAB";
	String privKey = "MIIEowIBAAKCAQEAmWsgewF82pdLQOiFyuOjkbhLBn31sfGsxlWiYNpFCzkZx9R/\n" +
			"tkQfw960HyDozmTWeQ4OMNrI3FSAFMvafAR6QqBtQ7/H7Tdo1/KtJMzCgprvAQr5\n" +
			"n4roAyH8CdlIC37AvYR/z6h9Ckvj2ZUzehHDMhpwvLYZ+waOtuoxU0/1/7pjb6+r\n" +
			"UpLvbsp/4Bm27g+FQw1skzDU7mCiHafHyjP//F2Mr9abYzArf9UTZMxtxJ9pQJZS\n" +
			"20zKsB9jT4vDEjQ9FCwWgY4bno3IPcCnOUrr3dzEgGpDauGWjEnWHtheQLzkKsBv\n" +
			"uPCo1QxwnbMU1rWdBmvi4GitDpMhU9083p2okQIDAQABAoIBAE3KIcf88x+rAv9A\n" +
			"Z0Z+shtbBL+f8optbhuKpDDTu5p7M3U9bBww4qJgM5htCV5NhuoOlGd1J8+AEQl6\n" +
			"a6fiZVOPIJfvkCHZrJGCfQRhxmaOxI0U0Ylx1z5vZupff8ZEWNo/ascSOYSVAkz6\n" +
			"+AT3KLAo8+zbsMS1iHt6t9P0gVlOkcivpD1rlJuySRHpxIHBnN1BrUErQCHdZc5i\n" +
			"9kEjKQC5t4tkd4vpd9U3pSzcnQOVX+TkG0F+dK3g1JMe5TaHfPO3isk1qtPsv/7I\n" +
			"hySGmhXagAdP+d0ituq3IhcgrfFdef6iu7eIDxpv3xHInf3u43Mt4yLVHImuyVrl\n" +
			"isdv7NkCgYEAyWv6Muwc3F6gzrfd3Oilf+RRjASnTWVwbAPLHTwXXfbwCNCaLfdR\n" +
			"ruWuS0lIRX/SdgRT3H6VvCM73xeGk/2T3ddVqAoO8sBjDyoHuXKflao7lhKel+RA\n" +
			"iaLhIxs0RK+AYlW1rCmWdiQejpS5nAvq0jsGRasWL4Q9/hCqw7f9m2MCgYEAwv1N\n" +
			"vPTkWP04RvsRMyC/IPF5KFm3LDBor+qdqLClKPaZmDuHSVlPcWksmk/L4aNW8jN2\n" +
			"N0U8YP6l5bgzlur9QQd2GSniYqZswuFF+NibG45kaf8q9T5U194BwPi95k4ru6gb\n" +
			"fngyObKlu3D2wwXEK+yuzG1zZ/6DJxn5d45sAHsCgYEAub9WwyEU2HB3kUrkUfVF\n" +
			"sjRGs34THv+99g5lgDdLQT8ZSre8h0k9TbHH0uvotxbSaj1BbORbh11iuDBEzjMZ\n" +
			"6onLFyT3dgvPDkvvRaib3HRZcOMI2AAJOCQ5xJswz2qdVZG+8N6FP7u9ZjVnGa2v\n" +
			"xmHiPdsxoW4tkR+jqswBFwsCgYBf/Bs5af/CQpxibJLx7SvIxrWShF9j9EyEVGTZ\n" +
			"tmMHACVpx9v34mv18wUOzTsazrItNeH6oS1wvcnihEN5BiI20bpz9qdHUo91ezlb\n" +
			"nxzzequ5de+qm81eGh4Y5Rlt9osWrFEkd3yZ5HQrCheetwbzbGY7oaFOzv220NV5\n" +
			"4fUOYwKBgD5Df+2+0eqlAmJ8W6UgXDF4iT+aqz6xzKIaKfsHX+XHK6wNkMBYJKYy\n" +
			"Knr7lRO5Z/83FCe7IfXWMoEQXhRU2rjSOMRA/1zL5Pr6kd5rVuuuJqo+UBWwIZdy\n" +
			"2d8AX7diETfaeV7KHaBhLmLRYi96HO4CGGQpBn7SfctpzOnXq3WF";


	public String encryptData(String dataToEncrypt) {
		// generate a new public/private key pair to test with (note. you should only do this once and keep them!)
		//KeyPair kp = getKeyPair();

		//PublicKey publicKey = kp.getPublic();
		//byte[] publicKeyBytes = publicKey.getEncoded();
		String publicKeyBytesBase64 = pubKey; //new String(Base64.encode(publicKeyBytes, Base64.DEFAULT));

		// encryption
		String encrypted = encryptRSAToString(dataToEncrypt, publicKeyBytesBase64);


		return encrypted;
	}

	public String decryptData(String encrypted) {
		// generate a new public/private key pair to test with (note. you should only do this once and keep them!)
		//KeyPair kp = getKeyPair();

		//PrivateKey privateKey = kp.getPrivate();
		//byte[] privateKeyBytes = privateKey.getEncoded();
		String privateKeyBytesBase64 = privKey; //new String(Base64.encode(privateKeyBytes, Base64.DEFAULT));


		// decryption
		String decrypted = decryptRSAToString(encrypted, privateKeyBytesBase64);

		return decrypted;
	}

	private static KeyPair getKeyPair() {
		KeyPair kp = null;
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			kp = kpg.generateKeyPair();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return kp;
	}

	private static String encryptRSAToString(String clearText, String publicKey) {
		String encryptedBase64 = "";
		try {
			KeyFactory keyFac = KeyFactory.getInstance("RSA");
			KeySpec keySpec = new X509EncodedKeySpec(Base64.decode(publicKey.trim().getBytes(), Base64.DEFAULT));
			Key key = keyFac.generatePublic(keySpec);

			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
			// encrypt the plain text using the public key
			cipher.init(Cipher.ENCRYPT_MODE, key);

			byte[] encryptedBytes = cipher.doFinal(clearText.getBytes("UTF-8"));
			encryptedBase64 = new String(Base64.encode(encryptedBytes, Base64.DEFAULT));
		} catch (Exception e) {
			e.printStackTrace();
		}

		return encryptedBase64.replaceAll("(\\r|\\n)", "");
	}

	private static String decryptRSAToString(String encryptedBase64, String privateKey) {

		String decryptedString = "";
		try {
			KeyFactory keyFac = KeyFactory.getInstance("RSA");
			KeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(privateKey.trim().getBytes(), Base64.DEFAULT));
			Key key = keyFac.generatePrivate(keySpec);

			// get an RSA cipher object and print the provider
			final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
			// encrypt the plain text using the public key
			cipher.init(Cipher.DECRYPT_MODE, key);

			byte[] encryptedBytes = Base64.decode(encryptedBase64, Base64.DEFAULT);
			byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
			decryptedString = new String(decryptedBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return decryptedString;
	}



}
