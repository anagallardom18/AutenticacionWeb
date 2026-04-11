package autenticacion;

import jakarta.mail.*;
import jakarta.mail.internet.*;
import java.util.Properties;
import java.security.SecureRandom;

/**
 * SERVICIO DE MENSAJERÍA SMTP (Correo)
 * Esta clase gestiona el envío de correos electrónicos para el sistema de 
 * autenticación multifactor. Utiliza el protocolo SMTP con cifrado TLS para 
 * garantizar la entrega segura de los códigos OTP (One-Time Password).
 */
public class Correo {

    private final Session session;
    private final String remitente;

    /**
     * Constructor del servicio de correo.
     * Utiliza la clase de utilidad SecurityUtil para el descifrado 
     * seguro de las credenciales SMTP almacenadas en la base de datos.
     */
    public Correo(ConfigService config) {
        // --- 1. CARGA DINÁMICA DE PARÁMETROS ---
        this.remitente = config.getValor("email_user"); 
        final String passCifrada = config.getValor("email_password"); 
        final String host = config.getValor("smtp_host");
        final String port = config.getValor("smtp_port");

        String passDescifradaAux = "";
        try {
            // 1. Decodificamos el Base64 que viene de la BD
            byte[] datosCompletos = org.apache.commons.codec.binary.Base64.decodeBase64(passCifrada);
            
            // 2. Extraemos los primeros 12 bytes 
            byte[] iv = new byte[12];
            System.arraycopy(datosCompletos, 0, iv, 0, 12);
            
            // 3. El resto de bytes son la contraseña cifrada
            byte[] cifradoReal = new byte[datosCompletos.length - 12];
            System.arraycopy(datosCompletos, 12, cifradoReal, 0, cifradoReal.length);
            
            // 4. Desciframos usando el IV real
            byte[] descifrado = SecurityUtil.decrypt(cifradoReal, iv);
            passDescifradaAux = new String(descifrado);
            
       
        } catch (Exception e) {
            System.err.println("ERROR CRÍTICO: No se pudo descifrar la contraseña del email. " + e.getMessage());
        }
        
        final String appContrasena = passDescifradaAux;


        // --- 2. CONFIGURACIÓN DEL PROTOCOLO SMTP ---
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true"); 
        props.put("mail.smtp.starttls.enable", "true"); 
        props.put("mail.smtp.starttls.required", "true");
        props.put("mail.smtp.ssl.protocols", "TLSv1.2");
        
        props.put("mail.smtp.host", (host != null && !host.isEmpty()) ? host : "smtp.gmail.com");
        props.put("mail.smtp.port", (port != null && !port.isEmpty()) ? port : "587");
        props.put("mail.smtp.user", this.remitente); 

        props.put("mail.smtp.connectiontimeout", "5000"); 
        props.put("mail.smtp.timeout", "5000"); 

        // --- 3. CREACIÓN DE LA SESIÓN AUTENTICADA ---
        this.session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(remitente, appContrasena);
            }
        });
    }

    /**
     * Genera un desafío numérico aleatorio (OTP) de 6 dígitos.
     * Se utiliza 'SecureRandom' para garantizar entropía criptográfica.
     * @return String con el código de 6 dígitos 
     */
    public static String generaOTP() {
        SecureRandom sr = new SecureRandom();
        // Rango de 100.000 a 999.999
        int codigo = 100000 + sr.nextInt(900000);
        return String.valueOf(codigo);
    }

    /**
     * Construye y envía el mensaje de correo electrónico con el desafío OTP.
     * @param destinatario Dirección de correo electrónico del usuario final.
     * @param otp Código generado que el usuario debe validar.
     * @throws Exception Si ocurre un fallo en el protocolo SMTP.
     */
    public void enviaCorreo(String destinatario, String otp) throws Exception {
        // Validación de integridad
        if (remitente == null || remitente.trim().isEmpty()) {
            throw new Exception("ERROR CRÍTICO: El parámetro 'email_user' no existe en la tabla settings.");
        }

        try {
            Message mensaje = new MimeMessage(session);
            
            // Configuración del emisor con un alias descriptivo
            mensaje.setFrom(new InternetAddress(remitente, "Seguridad Sistema"));
            
            // Configuración del receptor y asunto
            mensaje.setRecipient(Message.RecipientType.TO, new InternetAddress(destinatario));
            mensaje.setSubject("Código de verificación: " + otp);
            
            // Construcción del cuerpo del mensaje
            StringBuilder cuerpo = new StringBuilder();
            cuerpo.append("Se ha detectado una solicitud de acceso a su cuenta.\n\n");
            cuerpo.append("Su código de verificación es: ").append(otp).append("\n\n");
            cuerpo.append("Este código caducará en unos minutos.\n");
            cuerpo.append("Si no ha solicitado este acceso, por favor ignore este mensaje.");
            
            mensaje.setText(cuerpo.toString());

         
            Transport.send(mensaje);
            
            System.out.println("LOG [AUDITORÍA]: Desafío OTP enviado correctamente a: " + destinatario);

        } catch (MessagingException e) {
            // Captura fallos de red, autenticación o servidor SMTP
            throw new Exception("Error al intentar enviar el correo SMTP: " + e.getMessage());
        } catch (java.io.UnsupportedEncodingException e) {
            throw new Exception("Error en el formato del alias del remitente: " + e.getMessage());
        }
    }
}