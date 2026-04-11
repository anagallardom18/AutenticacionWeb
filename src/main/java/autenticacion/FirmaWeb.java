package autenticacion;

import java.security.*;
import java.security.spec.*;
import com.upokecenter.cbor.CBORObject;

/**
 * Validación de firmas criptográficas WebAuthn.
 * Soporta algoritmos ES256 (ECDSA sobre curva P-256).
 */
public class FirmaWeb {

    /**
     * Valida la firma WebAuthn usando una clave pública ES256 (P-256).
     *
     * @param authenticatorData bytes del authenticatorData recibidos del navegador
     * @param clientDataJSON bytes del clientDataJSON recibidos del navegador
     * @param signature firma ECDSA recibida
     * @param publicKeyBytes clave pública almacenada en BD en formato COSE
     * @return true si la firma es válida
     */
    public static boolean validarFirma(byte[] authenticatorData, byte[] clientDataJSON, byte[] signature, byte[] publicKeyBytes) {
        try {
            // 1. Convertir la clave pública de formato COSE a objeto PublicKey de Java
            PublicKey publicKey = coseToECPublicKey(publicKeyBytes);

            // 2. Calcular el hash SHA-256 del clientDataJSON
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] clientDataHash = digest.digest(clientDataJSON); 

            // 3. Concatenar: authenticatorData + clientDataHash para verificar sobre este bloque
            byte[] signedData = new byte[authenticatorData.length + clientDataHash.length];
            System.arraycopy(authenticatorData, 0, signedData, 0, authenticatorData.length);
            System.arraycopy(clientDataHash, 0, signedData, authenticatorData.length, clientDataHash.length);

            // 4. Verificar la firma ECDSA (SHA256withECDSA)
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(publicKey);
            sig.update(signedData); 

            return sig.verify(signature);

        } catch (Exception e) {
            System.err.println("Error en la validación de firma criptográfica: " + e.getMessage());
            return false;
        }
    }

    private static PublicKey coseToECPublicKey(byte[] coseKeyBytes) throws Exception {
        CBORObject cose = CBORObject.DecodeFromBytes(coseKeyBytes);
        
        // Mapeo de claves COSE según estándar RFC 8152
        // kty: 1, crv: -1, x: -2, y: -3
        CBORObject kty = cose.get(CBORObject.FromObject(1));
        CBORObject crv = cose.get(CBORObject.FromObject(-1));
        CBORObject xObj = cose.get(CBORObject.FromObject(-2));
        CBORObject yObj = cose.get(CBORObject.FromObject(-3));

        if (kty == null || crv == null || xObj == null || yObj == null) {
            throw new IllegalArgumentException("La clave COSE está incompleta o mal formada.");
        }

        // Verificar que sea EC (2) y curva P-256 (1)
        if (kty.AsInt32() != 2 || crv.AsInt32() != 1) {
            throw new IllegalArgumentException("Tipo de clave o curva no soportada. Se esperaba EC (2) y P-256 (1).");
        }
        
        byte[] x = xObj.GetByteString();
        byte[] y = yObj.GetByteString();

        if (x.length != 32 || y.length != 32) {
             throw new IllegalArgumentException("Longitud de coordenadas EC incorrecta.");
        }
        
        // Reconstrucción del punto no comprimido (0x04 + X + Y)
        byte[] uncompressed = new byte[65];
        uncompressed[0] = 0x04;
        System.arraycopy(x, 0, uncompressed, 1, 32);
        System.arraycopy(y, 0, uncompressed, 33, 32);

        // Convertir a formato X.509 (SubjectPublicKeyInfo) para que Java lo entienda
        byte[] spkiBytes = encodeToSubjectPublicKeyInfo(uncompressed); 

        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(new X509EncodedKeySpec(spkiBytes));
    }

   //Envuelve un punto EC no comprimido en una estructura ASN.1 SubjectPublicKeyInfo (SPKI).
    private static byte[] encodeToSubjectPublicKeyInfo(byte[] uncompressedPoint) {
        // Encabezado ASN.1 DER para una clave pública EC (P-256)
        byte[] spkiHeader = new byte[] {
            0x30, 0x59,                          // SEQUENCE, length 89
            0x30, 0x13,                          // SEQUENCE (AlgorithmIdentifier), length 19
            0x06, 0x07, 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x02, 0x01, // OID id-ecPublicKey
            0x06, 0x08, 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x03, 0x01, 0x07, // OID secp256r1
            0x03, 0x42, 0x00                     // BIT STRING, length 66 (0x00 padding + 65 bytes point)
        };

        byte[] spki = new byte[spkiHeader.length + uncompressedPoint.length];
        System.arraycopy(spkiHeader, 0, spki, 0, spkiHeader.length);
        System.arraycopy(uncompressedPoint, 0, spki, spkiHeader.length, uncompressedPoint.length);
        
        return spki;
    }
}