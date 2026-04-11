package autenticacion;

import java.util.Base64;

/*
 * Genera contraseña cifrada
 */
public class GeneradorPassword {
    public static void main(String[] args) {
        try {
            // 1. Contraseña de Gmail
            String passGmail = "abcd efgh ijkl mnop"; 
            
            // 2. Generamos un IV aleatorio de 12 bytes
            byte[] iv = new byte[12];
            new java.security.SecureRandom().nextBytes(iv);
            
            // 3. Ciframos usando SecurityUtil 
            byte[] cifrado = SecurityUtil.encrypt(passGmail.getBytes(), iv);
            
            // 4. Juntamos IV + CIFRADO
            byte[] resultadoCompleto = new byte[iv.length + cifrado.length];
            System.arraycopy(iv, 0, resultadoCompleto, 0, iv.length);
            System.arraycopy(cifrado, 0, resultadoCompleto, iv.length, cifrado.length);
            
            // 5. Convertimos a Base64 para la base de datos
            String valorParaBD = Base64.getEncoder().encodeToString(resultadoCompleto);
            
            System.out.println("COPIA ESTE CÓDIGO Y PÉGALO EN LA TABLA SETTINGS:");
            System.out.println(valorParaBD);

            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}