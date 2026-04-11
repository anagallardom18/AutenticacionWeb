package autenticacion;

import jakarta.servlet.ServletException;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Servlet encargado de la validación de contraseñas de un solo uso basadas en tiempo (TOTP).
 * Este componente gestiona el flujo de autenticación mediante aplicaciones como Google Authenticator
 * o Microsoft Authenticator, representando el factor de posesión (TENER).
 */
@WebServlet("/LoginTOTPServlet")
public class LoginTOTPServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private UsuarioDAO usuarioDAO;
    private ConfigService configService;
    private Correo servicioCorreo; 

    /**
     * Inicialización de recursos de base de datos y servicios de mensajería.
     */
    @Override
    public void init() throws ServletException {
        try {
            Context ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            this.usuarioDAO = new UsuarioDAO(ds);
            this.configService = new ConfigService(ds);
            this.servicioCorreo = new Correo(this.configService);
        } catch (Exception e) {
            throw new ServletException("Error inicializando servicios en LoginTOTPServlet", e);
        }
    }

    /**
     * Procesa la verificación del código de 6 dígitos enviado por el usuario.
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String dni = request.getParameter("dni");
        String totp = request.getParameter("totp");
        String modoLogin = request.getParameter("modoLogin"); // Identifica si es flujo 1FA o refuerzo MFA

        // 1. VALIDACIÓN DE ENTRADA
        if (esVacio(dni) || esVacio(totp)) {
            enviarError(request, response, "Rellene el DNI y el código TOTP.", modoLogin);
            return;
        }

        Usuario usuario = usuarioDAO.obtenerUsuarioPorDNI(dni);
        if (usuario == null || esVacio(usuario.getTotpSecret())) {
            enviarError(request, response, "Usuario no encontrado o servicio TOTP no vinculado.", modoLogin);
            return;
        }

        // 2. VALIDACIÓN ALGORÍTMICA (RFC 6238)
      
        boolean esValido = false;
        try {
            esValido = TOTPUtils.validarCodigo(usuario.getTotpSecret(), totp);
        } catch (Exception e) {
            enviarError(request, response, "Error técnico en el motor de validación TOTP.", modoLogin);
            return;
        }

        if (!esValido) {
            enviarError(request, response, "Código de seguridad incorrecto o caducado.", modoLogin);
            return;
        }

        // --- ÉXITO: GESTIÓN DE CATEGORÍAS DE AUTENTICACIÓN (TENER) ---
        HttpSession sesion = request.getSession(true);
        
        
        @SuppressWarnings("unchecked")
        List<String> superadas = (List<String>) sesion.getAttribute("categoriasSuperadas");
        
        if (superadas == null) superadas = new ArrayList<>();

        // El TOTP demuestra que el usuario POSEE el dispositivo vinculado
        if (!superadas.contains("TENER")) {
            superadas.add("TENER");
        }
        sesion.setAttribute("categoriasSuperadas", superadas);
        sesion.setAttribute("usuarioTemp", dni);



        // CASO A: ACCESO PASSWORDLESS (Login directo mediante TOTP)
        if ("1FA".equals(modoLogin)) {
        	usuarioDAO.resetearIntentos(dni);
            sesion.setAttribute("usuario", dni); 
            response.sendRedirect("bienvenido.jsp");
            return;
        }

        // CASO B: CUMPLIMIENTO DE MULTI-FACTOR (MFA)
        // Si el usuario ya superó otra categoría, se le concede acceso.
        if (superadas.size() >= 2) {
        	usuarioDAO.resetearIntentos(dni);
            sesion.setAttribute("usuario", dni);
            response.sendRedirect("bienvenido.jsp");
            return;
        }

        // CASO C: REFUERZO MEDIANTE OTROS FACTORES (Step-up Authentication)
        String correo = usuario.getCorreo();
        if (esVacio(correo)) {
            // Si no hay correo para OTP, se deriva a alternativas biométricas o físicas
            response.sendRedirect("loginAlternativo.jsp");
            return;
        }

        // Generación de un nuevo desafío (OTP por correo) para completar el MFA
        String otp = Correo.generaOTP();
        sesion.setAttribute("otp", otp);

        try {
            servicioCorreo.enviaCorreo(correo, otp);
            request.getRequestDispatcher("verificaOTP.jsp").forward(request, response);
        } catch (Exception e) {
            enviarError(request, response, "Fallo al enviar el correo de verificación secundaria.", "2FA");
        }
    }

    /**
     * Centraliza el manejo de errores y redirecciones según el origen de la petición.
     */
    private void enviarError(HttpServletRequest req, HttpServletResponse resp, String msg, String modo) 
            throws ServletException, IOException {
        req.setAttribute("error", msg);
        req.setAttribute("dniRecordado", req.getParameter("dni"));
        // Si el error viene de un flujo secundario, se mantiene en loginAlternativo
        String destino = "2FA".equals(modo) ? "loginAlternativo.jsp" : "login1fa.jsp";
        req.getRequestDispatcher(destino).forward(req, resp);
    }

    /**
     * Utilidad de validación de cadenas.
     */
    private boolean esVacio(String s) { return s == null || s.trim().isEmpty(); }
}