package autenticacion;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import org.apache.commons.codec.binary.Base32;

public class TOTPUtils {

    public static boolean validarCodigo(String secretBase32, String codigoIngresado) throws Exception {
        long timeIndex = Instant.now().getEpochSecond() / 30; 

        Base32 base32 = new Base32();
        byte[] secretKey = base32.decode(secretBase32);

        for (long i = -1; i <= 1; i++) {
            String generated = generarTOTP(secretKey, timeIndex + i);
            if (generated.equals(codigoIngresado)) {
                return true;
            }
        }
        return false;
    }

    private static String generarTOTP(byte[] key, long timeIndex) throws Exception {
        byte[] data = new byte[8];
        for (int i = 7; i >= 0; i--) {
            data[i] = (byte) (timeIndex & 0xFF);
            timeIndex >>= 8;
        }

        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(key, "HmacSHA1"));
        byte[] hash = mac.doFinal(data);

        int offset = hash[hash.length - 1] & 0xF;
        int binary =
                ((hash[offset] & 0x7F) << 24) |
                ((hash[offset + 1] & 0xFF) << 16) |
                ((hash[offset + 2] & 0xFF) << 8) |
                (hash[offset + 3] & 0xFF);

        int otp = binary % 1000000; 
        return String.format("%06d", otp);
    }
}
