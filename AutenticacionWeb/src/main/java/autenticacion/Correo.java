package autenticacion;
import jakarta.mail.*;
import jakarta.mail.internet.*;
import java.util.*;
import java.util.Properties;
import java.util.Random;

public class Correo {

	public static String generaOTP() {
		Random numAleatorio = new Random();
		int codigo = 100000 + numAleatorio.nextInt(900000);
		return String.valueOf(codigo);
	}
	
	
	public static void enviaCorreo(String destinatario, String otp) {
		final String remitente = "correoenviootp@gmail.com";
		final String appContrasena = "lslp bprw srpq ncyq";
		

        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
		
        Session session = Session.getInstance(props, new Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(remitente, appContrasena);
            }
        });

        try {
            Message mensaje = new MimeMessage(session);
            mensaje.setFrom(new InternetAddress(remitente));
            mensaje.setRecipients(Message.RecipientType.TO, InternetAddress.parse(destinatario));
            mensaje.setSubject("Código de verificación 2FA");
            mensaje.setText("Código de verificación es: " + otp);

            Transport.send(mensaje);
            System.out.println("Correo enviado a " + destinatario);

        } 
        catch (MessagingException e) {
            e.printStackTrace();
        }
	}

}
