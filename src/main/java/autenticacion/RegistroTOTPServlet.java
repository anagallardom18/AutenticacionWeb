package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.util.Base64;

import com.google.zxing.*;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;

import org.apache.commons.codec.binary.Base32;

/**
 * Servlet para configurar la Autenticación mediante TOTP.
 * Genera claves secretas, códigos QR y valida la vinculación inicial.
 */
@WebServlet("/RegistroTOTPServlet")
public class RegistroTOTPServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private UsuarioDAO usuarioDAO;

    @Override
    public void init() throws ServletException {
        try {
            // Inicialización del acceso a datos mediante JNDI
            Context ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            usuarioDAO = new UsuarioDAO(ds);
        } catch (Exception e) {
            throw new ServletException("Error inicializando UsuarioDAO", e);
        }
    }

    /**
     * PROCESO DE VERIFICACIÓN (doPost):
     * Se ejecuta cuando el usuario introduce el código de su app móvil para confirmar el registro.
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);
        // Seguridad: Verificar que hay una sesión activa
        if (session == null || session.getAttribute("usuario") == null) {
            response.sendRedirect("login.jsp");
            return;
        }

        String dni = (String) session.getAttribute("usuario");
        String codigoIngresado = request.getParameter("codigo");

        try {
            Usuario usuario = usuarioDAO.obtenerUsuarioPorDNI(dni);
            if (usuario == null) {
                request.setAttribute("error", "Usuario no encontrado");
                request.getRequestDispatcher("configurarTOTP.jsp").forward(request, response);
                return;
            }

            String secret = usuario.getTotpSecret();
            // Validar que el usuario realmente inició el proceso de configuración
            if (secret == null || secret.isEmpty()) {
                request.setAttribute("error", "El TOTP no ha sido configurado aún");
                request.getRequestDispatcher("configurarTOTP.jsp").forward(request, response);
                return;
            }

            // Uso de clase de utilidad para comparar el código introducido con el esperado según el secreto
            boolean valido = TOTPUtils.validarCodigo(secret, codigoIngresado);

            if (valido) {
                // Si es correcto, el usuario ha vinculado su móvil con éxito
                response.sendRedirect("bienvenido.jsp");
            } else {
                request.setAttribute("error", "Código TOTP incorrecto");
                request.getRequestDispatcher("configurarTOTP.jsp").forward(request, response);
            }

        } catch (Exception e) {
            throw new ServletException(e);
        }
    }

    /**
     * PROCESO DE PREPARACIÓN (doGet):
     * Genera la clave secreta y el código QR para que el usuario lo escanee.
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("usuario") == null) {
            response.sendRedirect("login.jsp");
            return;
        }

        String dni = (String) session.getAttribute("usuario");

        try {
            Usuario usuario = usuarioDAO.obtenerUsuarioPorDNI(dni);
            if (usuario == null) {
                response.sendError(404, "Usuario no encontrado");
                return;
            }

            String secretBase32;

            // 1. GENERACIÓN DE CLAVE ÚNICA:
            // Solo creamos una clave nueva si el usuario no tiene una previa.
            if (usuario.getTotpSecret() == null || usuario.getTotpSecret().isEmpty()) {
                // Generamos un HmacSHA1 de 160 bits (estándar para TOTP)
                KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1");
                keyGen.init(160);
                SecretKey secretKey = keyGen.generateKey();

                // El secreto debe estar en Base32 para ser compatible con Google Authenticator
                Base32 base32 = new Base32();
                secretBase32 = base32.encodeToString(secretKey.getEncoded()).replace("=", "");

                // Guardamos el secreto en la base de datos de forma permanente
                usuario.setTotpSecret(secretBase32);
                usuarioDAO.actualizarTotpSecret(usuario);
            } else {
                // Si ya existe, reutilizamos la actual para mostrar el QR de nuevo si es necesario
                secretBase32 = usuario.getTotpSecret();
            }

            // 2. CONSTRUCCIÓN DEL URI (otpauth):
            // Formato estándar que entienden las aplicaciones de autenticación
            String otpauth = "otpauth://totp/AutenticacionWeb:" + dni +
                    "?secret=" + secretBase32 +
                    "&issuer=AutenticacionWeb";

            // 3. GENERACIÓN DEL CÓDIGO QR:
            // Convertimos el URI de texto en una matriz de puntos (QR) de 200x200
            QRCodeWriter qrWriter = new QRCodeWriter();
            BitMatrix matrix = qrWriter.encode(otpauth, BarcodeFormat.QR_CODE, 200, 200);

            // Convertimos la imagen a un flujo de bytes PNG
            ByteArrayOutputStream pngOutput = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(matrix, "PNG", pngOutput);

            // Codificamos la imagen en Base64 para incrustarla directamente en el HTML (Data URI)
            String base64QR = Base64.getEncoder().encodeToString(pngOutput.toByteArray());

            // Enviamos los datos a la página JSP
            request.setAttribute("qrUrl", "data:image/png;base64," + base64QR);
            request.setAttribute("secret", secretBase32);

            request.getRequestDispatcher("configurarTOTP.jsp").forward(request, response);

        } catch (Exception e) {
            throw new ServletException(e);
        }
    }
}