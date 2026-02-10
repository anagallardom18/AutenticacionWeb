package autenticacion;

public class PublicKeyExtractor {

   
    public static class AttestationResult {
        private byte[] publicKeyCose; 
        private long signCount;

        public AttestationResult(byte[] publicKeyCose, long signCount) {
            this.publicKeyCose = publicKeyCose;
            this.signCount = signCount;
        }

        public byte[] getPublicKeyCose() { return publicKeyCose; }
        public long getSignCount() { return signCount; }
    }

    public static AttestationResult parseAuthenticatorData(byte[] authenticatorData) {
        if (authenticatorData == null || authenticatorData.length < 37) {
            throw new IllegalArgumentException("authenticatorData demasiado corto");
        }

        //los primeros 32 bytes son rpIdHash
        int index = 32;

        //1 byte flags
        byte flags = authenticatorData[index];
        index += 1;

        //4 bytes big-endian counter de firma
        long signCount = ((authenticatorData[index] & 0xFFL) << 24) |
                         ((authenticatorData[index + 1] & 0xFFL) << 16) |
                         ((authenticatorData[index + 2] & 0xFFL) << 8) |
                         (authenticatorData[index + 3] & 0xFFL);

        return new AttestationResult(null, signCount);
    }

 
    public static AttestationResult parseAttestation(byte[] attestationObject) {
        return new AttestationResult(null, 0);
    }
}
