package autenticacion;

import jakarta.servlet.*;

import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;

import com.google.zxing.*;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import org.apache.commons.codec.binary.Base32;

@WebServlet("/ConfigurarTOTPServlet")
public class ConfigurarTOTPServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("usuario") == null) {
            response.sendRedirect("login.jsp");
            return;
        }

        String dni = (String) session.getAttribute("usuario");
        String codigoIngresado = request.getParameter("codigo");

        try {
            //recuperar el usuario usando UsuarioDAO
            Usuario usuario = UsuarioDAO.obtenerUsuarioPorDNI(dni);
            if (usuario == null) {
                request.setAttribute("error", "Usuario no encontrado");
                request.getRequestDispatcher("configurarTOTP.jsp").forward(request, response);
                return;
            }

            String secret = usuario.getTotpSecret();
            if (secret == null || secret.isEmpty()) {
                request.setAttribute("error", "El TOTP no ha sido configurado aún");
                request.getRequestDispatcher("configurarTOTP.jsp").forward(request, response);
                return;
            }

            //validar TOTP
            boolean valido = TOTPUtils.validarCodigo(secret, codigoIngresado);

            if (valido) {
                response.sendRedirect("bienvenido.jsp"); 
            } else {
                request.setAttribute("error", "Código TOTP incorrecto");
                request.getRequestDispatcher("configurarTOTP.jsp").forward(request, response);
            }

        } catch (Exception e) {
            throw new ServletException(e);
        }
    }

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
            //generar secreto HMAC-SHA1
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1");
            keyGen.init(160);
            SecretKey secretKey = keyGen.generateKey();

            Base32 base32 = new Base32();
            String secretBase32 = base32.encodeToString(secretKey.getEncoded());
            secretBase32 = secretBase32.replace("=", "");

            //guardar el secreto usando UsuarioDAO
            Usuario usuario = UsuarioDAO.obtenerUsuarioPorDNI(dni);
            if (usuario == null) {
                request.setAttribute("error", "Usuario no encontrado");
                request.getRequestDispatcher("configurarTOTP.jsp").forward(request, response);
                return;
            }
            usuario.setTotpSecret(secretBase32);
            UsuarioDAO.actualizarTotpSecret(usuario); 

            //crear URL TOTP
            String otpauth = "otpauth://totp/AutenticacionWeb:" + dni +
                    "?secret=" + secretBase32 +
                    "&issuer=AutenticacionWeb";

            //generar QR
            QRCodeWriter qrWriter = new QRCodeWriter();
            BitMatrix matrix = qrWriter.encode(otpauth, BarcodeFormat.QR_CODE, 200, 200);

            ByteArrayOutputStream pngOutput = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(matrix, "PNG", pngOutput);

            String base64QR = Base64.getEncoder().encodeToString(pngOutput.toByteArray());

            //pasar al JSP
            request.setAttribute("qrUrl", "data:image/png;base64," + base64QR);
            request.setAttribute("secret", secretBase32);

            request.getRequestDispatcher("configurarTOTP.jsp").forward(request, response);

        } catch (Exception e) {
            throw new ServletException(e);
        }
    }
}
