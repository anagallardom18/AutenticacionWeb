package autenticacion;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import org.apache.commons.codec.binary.Base32;

/**
 * Utilidad para la validación de algoritmos TOTP (RFC 6238).
 * Compatible con Google Authenticator, Authy y Microsoft Authenticator.
 */
public class TOTPUtils {

    private static final int INTERVALO_SEGUNDOS = 30;
    private static final int VENTANA_TIEMPO = 1; // Permite t-1, t, t+1

    /**
     * Valida si el código introducido es correcto para el secreto dado.
     */
    public static boolean validarCodigo(String secretBase32, String codigoIngresado) {
        if (secretBase32 == null || codigoIngresado == null || codigoIngresado.length() != 6) {
            return false;
        }

        try {
            // Limpieza del secreto (eliminar espacios y pasar a mayúsculas para Base32)
            String cleanSecret = secretBase32.replace(" ", "").toUpperCase();
            Base32 base32 = new Base32();
            byte[] secretKey = base32.decode(cleanSecret);

            // Índice de tiempo actual (instantes de 30 segundos desde la época Unix)
            long timeIndex = Instant.now().getEpochSecond() / INTERVALO_SEGUNDOS;

            // Probamos el código actual, el anterior y el siguiente para compensar desfases de reloj
            for (int i = -VENTANA_TIEMPO; i <= VENTANA_TIEMPO; i++) {
                String generated = generarTOTP(secretKey, timeIndex + i);
                if (generated.equals(codigoIngresado)) {
                    return true;
                }
            }
        } catch (Exception e) {
            // En utilidades de seguridad, es mejor no propagar el error y devolver falso
            System.err.println("Error validando TOTP: " + e.getMessage());
        }
        return false;
    }

    /**
     * Implementación interna del algoritmo HOTP basado en tiempo.
     */
    private static String generarTOTP(byte[] key, long timeIndex) throws Exception {
        // Convertir el índice de tiempo a un array de 8 bytes (Big-Endian)
        byte[] data = new byte[8];
        long temp = timeIndex;
        for (int i = 7; i >= 0; i--) {
            data[i] = (byte) (temp & 0xFF);
            temp >>= 8;
        }

        // HMAC-SHA1
        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);
        byte[] hash = mac.doFinal(data);

        // Truncamiento dinámico (Dynamic Truncation)
        int offset = hash[hash.length - 1] & 0xF;
        int binary =
                ((hash[offset] & 0x7F) << 24) |
                ((hash[offset + 1] & 0xFF) << 16) |
                ((hash[offset + 2] & 0xFF) << 8) |
                (hash[offset + 3] & 0xFF);

        // Obtener los últimos 6 dígitos
        int otp = binary % 1_000_000; 
        return String.format("%06d", otp);
    }
}