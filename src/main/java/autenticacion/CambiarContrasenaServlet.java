package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;
import java.io.IOException;

/**
 * Servlet encargado de la gestión de recuperación y cambio de credenciales.
 * Implementa un flujo de verificación en dos pasos: validación de identidad 
 * mediante OTP y actualización del factor de conocimiento (contraseña).
 */
@WebServlet("/CambiarContrasenaServlet")
public class CambiarContrasenaServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    
    /**
     * Expresión regular para validar la política de contraseñas:
     * Al menos un número, una letra y exactamente 8 caracteres.
     */
    private static final String PASSWORD_REGEX = "^(?=.*[0-9])(?=.*[a-zA-Z]).{8}$";
    
    private UsuarioDAO usuarioDAO;
    private ConfigService configService; 
    private Correo servicioCorreo;

    /**
     * Inicialización de servicios mediante JNDI para asegurar la persistencia
     * de la configuración de correo y acceso a datos.
     */
    @Override
    public void init() throws ServletException {
        try {
            Context ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            usuarioDAO = new UsuarioDAO(ds);
            configService = new ConfigService(ds); 
            
            // Inicialización del servicio de correo con la configuración de la BD
            this.servicioCorreo = new Correo(this.configService);
        } catch (Exception e) {
            throw new ServletException("Error inicializando servicios en CambiarContrasenaServlet", e);
        }
    }

    /**
     * Orquestador de acciones de recuperación.
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String accion = request.getParameter("accion");

        if (accion == null) {
            response.sendRedirect("login.jsp");
            return;
        }

        switch (accion) {
            case "enviarOTP":
                enviarOTPRecuperacion(request, response);
                break;
            case "cambiarContrasena":
                cambiarContrasena(request, response);
                break;
            default:
                response.sendRedirect("login.jsp");
        }
    }

    /**
     * Primer paso del flujo: Valida que el DNI y correo pertenezcan al mismo usuario
     * y envía un código de un solo uso (OTP).
     */
    private void enviarOTPRecuperacion(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String dni = request.getParameter("dni");
        String correo = request.getParameter("correo");

        // Validación de campos obligatorios
        if (esNuloOVacio(dni) || esNuloOVacio(correo)) {
            mostrarError(request, response, "recuperarContrasena.jsp", "Todos los campos son obligatorios.");
            return;
        }

        // Validación de existencia y vinculación en la BD
        Usuario usuario = usuarioDAO.obtenerUsuarioPorDNI(dni);
        if (usuario == null || !correo.equalsIgnoreCase(usuario.getCorreo())) {
            // Se usa un mensaje genérico por seguridad para evitar enumeración de usuarios
            mostrarError(request, response, "recuperarContrasena.jsp", "Los datos introducidos no coinciden con nuestros registros.");
            return;
        }

        // Generación de token temporal y almacenamiento en sesión
        String otp = Correo.generaOTP();
        HttpSession sesion = request.getSession(true);
        
        sesion.setAttribute("recuperacion", true); // Flag de estado de recuperación
        sesion.setAttribute("otpRecuperacion", otp);
        sesion.setAttribute("emailRecuperacion", correo);
        sesion.setAttribute("dniRecuperacion", dni);

        try {
            // Envío del desafío al factor de posesión (correo electrónico)
            servicioCorreo.enviaCorreo(correo, otp);
            
            // Redirección al verificador de OTP con parámetro de contexto
            response.sendRedirect("verificaOTP.jsp?origen=recuperacion");
        } catch (Exception e) {
            e.printStackTrace();
            mostrarError(request, response, "recuperarContrasena.jsp", 
                "No se pudo enviar el correo de recuperación. Inténtelo más tarde.");
        }
    }

    /**
     * Segundo paso del flujo: Valida la nueva contraseña contra las políticas
     * de seguridad y actualiza la base de datos.
     */
    private void cambiarContrasena(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Se recupera la sesión sin crear una nueva para validar el flujo previo
        HttpSession sesion = request.getSession(false);

        // Control de acceso: Si no hay sesión de recuperación activa, se expulsa al usuario
        if (sesion == null || sesion.getAttribute("dniRecuperacion") == null 
            || sesion.getAttribute("recuperacion") == null) {
            response.sendRedirect("index.jsp");
            return;
        }

        String nuevaContrasena = request.getParameter("nuevaContrasena");
        String repetirContrasena = request.getParameter("repetirContrasena");
        String dni = (String) sesion.getAttribute("dniRecuperacion");

        // 1. Validación de integridad de campos
        if (esNuloOVacio(nuevaContrasena) || esNuloOVacio(repetirContrasena)) {
            mostrarError(request, response, "cambiarContrasena.jsp", "Debe completar ambos campos.");
            return;
        }

        // 2. Validación de Política de Seguridad (Regex)
        if (!nuevaContrasena.matches(PASSWORD_REGEX)) {
            mostrarError(request, response, "cambiarContrasena.jsp", 
                "La contraseña debe tener 8 caracteres e incluir letras y números.");
            return;
        }

        // 3. Validación de coincidencia
        if (!nuevaContrasena.equals(repetirContrasena)) {
            mostrarError(request, response, "cambiarContrasena.jsp", "Las contraseñas no coinciden.");
            return;
        }

        try {
            Usuario usuario = usuarioDAO.obtenerUsuarioPorDNI(dni);
            if (usuario != null) {
                // Persistencia de la nueva credencial
                usuarioDAO.actualizarContrasena(dni, nuevaContrasena);
                
                // Invalida la sesión actual para forzar un nuevo login limpio
                sesion.invalidate();
                
                request.setAttribute("mensaje", "Contraseña actualizada correctamente. Ya puede iniciar sesión.");
                request.getRequestDispatcher("login.jsp").forward(request, response);
            } else {
                response.sendRedirect("index.jsp");
            }
        } catch (Exception e) {
            mostrarError(request, response, "cambiarContrasena.jsp", "Error técnico al actualizar en la base de datos.");
        }
    }

    /**
     * Utilidad para comprobación de cadenas vacías.
     */
    private boolean esNuloOVacio(String str) {
        return str == null || str.trim().isEmpty();
    }

    /**
     * Método centralizado para el manejo de feedback negativo al usuario.
     */
    private void mostrarError(HttpServletRequest req, HttpServletResponse resp, String vista, String msg) 
            throws ServletException, IOException {
        req.setAttribute("error", msg);
        req.getRequestDispatcher(vista).forward(req, resp);
    }
}