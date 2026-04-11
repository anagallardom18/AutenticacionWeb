package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;
import java.io.IOException;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;

/**
 * Servlet encargado de la validación final de los códigos OTP (One-Time Password).
 * Actúa como un controlador de flujo que bifurca la lógica según el contexto:
 * 1. Recuperación de credenciales.
 * 2. Segundo factor de autenticación (2FA) durante el acceso.
 */
@WebServlet("/OTPServlet")
public class OTPServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private UsuarioDAO usuarioDAO;

    @Override
    public void init() throws ServletException {
        try {
            Context ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            this.usuarioDAO = new UsuarioDAO(ds);
        } catch (Exception e) {
            throw new ServletException("Error al conectar OTPServlet con la base de datos", e);
        }
    }

    /**
     * Procesa la validación del código enviado por el usuario.
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

    	// Se recupera la sesión actual sin crear una nueva para garantizar la continuidad del flujo
        HttpSession sesion = request.getSession(false); 
        if (sesion == null) {
            response.sendRedirect("login1fa.jsp");
            return;
        }

        String codigoIntroducido = request.getParameter("otp");
        Boolean esRecuperacion = (Boolean) sesion.getAttribute("recuperacion");

        // --- FLUJO A: RECUPERACIÓN DE CONTRASEÑA ---
        // Se activa cuando el usuario ha solicitado resetear su contraseña desde CambiarContrasenaServlet
        if (esRecuperacion != null && esRecuperacion) {
            String otpCorrecto = (String) sesion.getAttribute("otpRecuperacion");
            String dniRecup = (String) sesion.getAttribute("dniRecuperacion");

            // Validación del secreto temporal
            if (codigoIntroducido != null && codigoIntroducido.equals(otpCorrecto)) {
            	  // ÉXITO: Se concede permiso para acceder al formulario de cambio de clave y se resetea los intentos
                usuarioDAO.resetearIntentos(dniRecup); 
                
                sesion.setAttribute("permisoCambio", true); 
                sesion.removeAttribute("otpRecuperacion");
                response.sendRedirect("cambiarContrasena.jsp");
            } else {
                request.setAttribute("error", "Código de recuperación incorrecto.");
                request.getRequestDispatcher("verificaOTP.jsp").forward(request, response);
            }

            // --- FLUJO B: SEGUNDO FACTOR DE AUTENTICACIÓN (LOGIN) ---
            // Se activa durante el proceso normal de inicio de sesión (MFA)
        } else {
            String otpCorrecto = (String) sesion.getAttribute("otp");
            String usuarioTemp = (String) sesion.getAttribute("usuarioTemp");

            if (codigoIntroducido != null && codigoIntroducido.equals(otpCorrecto)) {
            	// LOGIN EXITOSO: El usuario ha demostrado posesión del factor (Email/OTP)
                
                // Reseteo de intentos
                usuarioDAO.resetearIntentos(usuarioTemp);
                
                sesion.setAttribute("usuario", usuarioTemp);
             // Limpieza de credenciales temporales en memoria
                sesion.removeAttribute("otp");
                sesion.removeAttribute("usuarioTemp");
                response.sendRedirect("bienvenido.jsp");
            } else {
                request.setAttribute("error", "El código OTP introducido es incorrecto.");
             // Redirección interna para permitir al usuario reintentar el código
                request.getRequestDispatcher("verificaOTP.jsp").forward(request, response);
            }
        }
    }

    /**
     * Seguridad: Impide el acceso a la validación mediante peticiones GET (URL directa).
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.sendRedirect("login1fa.jsp");
    }
}