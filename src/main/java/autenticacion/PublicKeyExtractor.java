package autenticacion;

import com.upokecenter.cbor.CBORObject;
import java.util.Arrays;

/**
 * Clase de utilidad para desglosar los datos de autenticación de WebAuthn/FIDO2.
 * Extrae la Clave Pública (COSE), el Contador de Firmas y el Credential ID.
 */
public class PublicKeyExtractor {

    public static class AttestationResult {
        private byte[] publicKeyCose; 
        private long signCount;
        private byte[] credentialId;

        public AttestationResult(byte[] publicKeyCose, long signCount, byte[] credentialId) {
            this.publicKeyCose = publicKeyCose;
            this.signCount = signCount;
            this.credentialId = credentialId;
        }

        public byte[] getPublicKeyCose() { return publicKeyCose; }
        public long getSignCount() { return signCount; }
        public byte[] getCredentialId() { return credentialId; }
    }

    //Procesa el objeto de atestación (formato CBOR).
    public static AttestationResult parseAttestation(byte[] attestationObjectBytes) throws Exception {
        // Decodificamos el binario CBOR
        CBORObject attestationObj = CBORObject.DecodeFromBytes(attestationObjectBytes);
        
        // En esta librería, la forma más segura de comprobar una llave es intentar obtenerla
        // y verificar si el resultado es nulo.
        CBORObject authDataObj = attestationObj.get(CBORObject.FromObject("authData"));

        if (authDataObj == null) {
            throw new IllegalArgumentException("El objeto de atestación no contiene la clave 'authData'.");
        }

        byte[] authData = authDataObj.GetByteString();
        return parseAuthenticatorData(authData);
    }

    /**
     * Desglosa el binario authData siguiendo la estructura técnica de WebAuthn.
     */
    public static AttestationResult parseAuthenticatorData(byte[] authData) {
        // Estructura mínima obligatoria: 37 bytes
        if (authData == null || authData.length < 37) {
            throw new IllegalArgumentException("authData demasiado corto.");
        }

        // 1. rpIdHash (32 bytes) -> Ignoramos
        int index = 32;

        // 2. Flags (1 byte)
        byte flags = authData[index];
        index += 1;

        // Bit 6 (0x40): AT (Attested Credential Data Present)
        boolean hasAttestedCredentialData = (flags & 0x40) != 0;

        // 3. Counter (4 bytes Big-Endian)
        long signCount = ((authData[index] & 0xFFL) << 24) |
                         ((authData[index + 1] & 0xFFL) << 16) |
                         ((authData[index + 2] & 0xFFL) << 8) |
                         (authData[index + 3] & 0xFFL);
        index += 4;

        byte[] credentialId = null;
        byte[] publicKeyCose = null;

        // 4. Extraer datos si el flag AT está activo
        if (hasAttestedCredentialData) {
            // AAGUID (16 bytes)
            index += 16;

            // Longitud del Credential ID (2 bytes Big-Endian)
            if (index + 2 > authData.length) throw new IllegalArgumentException("authData malformado");
            int idLen = ((authData[index] & 0xFF) << 8) | (authData[index + 1] & 0xFF);
            index += 2;

            // Credential ID
            if (index + idLen > authData.length) throw new IllegalArgumentException("ID de credencial fuera de rango");
            credentialId = Arrays.copyOfRange(authData, index, index + idLen);
            index += idLen;

            // El resto es la clave pública en formato COSE
            publicKeyCose = Arrays.copyOfRange(authData, index, authData.length);
        }

        return new AttestationResult(publicKeyCose, signCount, credentialId);
    }
}