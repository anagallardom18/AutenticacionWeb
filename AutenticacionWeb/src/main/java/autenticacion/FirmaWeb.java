package autenticacion;


import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import com.upokecenter.cbor.CBORObject;



public class FirmaWeb {

    /***
     * Valida la firma WebAuthn usando una clave pública ES256 (P-256)
     *
     * @param authenticatorData bytes del authenticatorData
     * @param clientDataJSON bytes del clientDataJSON
     * @param signature firma ECDSA recibida del navegador
     * @param publicKeyBytes clave pública almacenada en BD (COSE)
     * @return true si la firma es correcta
     */
	public static boolean validarFirma(byte[] authenticatorData, byte[] clientDataJSON, byte[] signature, byte[] publicKeyBytes) {

		try {
			//convertir clave pública
			PublicKey publicKey = coseToECPublicKey(publicKeyBytes);

			//calcular el hash SHA-256
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] clientDataHash = digest.digest(clientDataJSON); 

			//concatenar authenticatorData + clientDataHash
			byte[] signedData = new byte[authenticatorData.length + clientDataHash.length];
			System.arraycopy(authenticatorData, 0, signedData, 0, authenticatorData.length);
			System.arraycopy(clientDataHash, 0, signedData, authenticatorData.length, clientDataHash.length);

			//verificar ECDSA
			Signature sig = Signature.getInstance("SHA256withECDSA");
			sig.initVerify(publicKey);
			sig.update(signedData); 

			return sig.verify(signature);

		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

    private static PublicKey coseToECPublicKey(byte[] coseKeyBytes) throws Exception {

        CBORObject cose = CBORObject.DecodeFromBytes(coseKeyBytes);
        
    
        CBORObject ktyKey = CBORObject.FromObject(1); // Key Type (kty)
        CBORObject crvKey = CBORObject.FromObject(-1); // Curve (crv)
        CBORObject xKey = CBORObject.FromObject(-2); // X coordinate
        CBORObject yKey = CBORObject.FromObject(-3); // Y coordinate
        
  
        CBORObject kty = cose.get(ktyKey);
        if (kty == null) {
            throw new IllegalArgumentException("COSE key missing mandatory KTY (key 1).");
        }
        
  
        CBORObject crv = cose.get(crvKey);
        if (crv == null) {
            throw new IllegalArgumentException("COSE key missing mandatory CRV (key -1).");
        }

     
        if (kty.AsInt32() != 2 || crv.AsInt32() != 1) {
            throw new IllegalArgumentException("Unsupported COSE key type or curve. Expected EC (2) and P-256 (1).");
        }

     
        CBORObject xObj = cose.get(xKey);
        CBORObject yObj = cose.get(yKey);

        if (xObj == null || yObj == null) {
             throw new IllegalArgumentException("COSE key missing mandatory X (key -2) or Y (key -3) coordinates.");
        }
        
        byte[] x = xObj.GetByteString();
        byte[] y = yObj.GetByteString();

       
        if (x.length != 32 || y.length != 32) {
             throw new IllegalArgumentException("EC key coordinates have incorrect length.");
        }
        
        
        byte[] uncompressed = new byte[1 + x.length + y.length];
        uncompressed[0] = 0x04;
        System.arraycopy(x, 0, uncompressed, 1, x.length);
        System.arraycopy(y, 0, uncompressed, 1 + x.length, y.length);


        byte[] spkiBytes = encodeToSubjectPublicKeyInfo(uncompressed); 

       
        KeyFactory kf = KeyFactory.getInstance("EC");
        EncodedKeySpec keySpec = new X509EncodedKeySpec(spkiBytes);

        return kf.generatePublic(keySpec);
    }

 
    private static byte[] encodeToSubjectPublicKeyInfo(byte[] uncompressedPoint) {
     
    	if (uncompressedPoint.length != 65) {
            throw new IllegalArgumentException("Expected 65-byte uncompressed point, got " + uncompressedPoint.length);
        }
    	
    	byte[] spkiHeader = new byte[] {
    	      
    	        0x30, (byte) 0x59, 	    
    	        0x30, 0x13, 
    	        0x06, 0x07, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x02, 0x01,
    	       
    	        0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07,
    	     
    	        0x03, 0x42,
    	        0x00 
    	    };

  
        byte[] spki = new byte[spkiHeader.length + uncompressedPoint.length];
        System.out.println("Header length generated: " + spkiHeader.length);
        System.arraycopy(spkiHeader, 0, spki, 0, spkiHeader.length);
        System.arraycopy(uncompressedPoint, 0, spki, spkiHeader.length, uncompressedPoint.length);
        
        return spki;
    }
}