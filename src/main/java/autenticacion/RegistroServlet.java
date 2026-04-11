package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;
import java.io.IOException;
import javax.naming.InitialContext;
import javax.sql.DataSource;

/**
 * Servlet encargado del registro de nuevos usuarios.
 */
@WebServlet("/RegistroServlet")
public class RegistroServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    
    // REGEX: Fuerza una contraseña de exactamente 8 caracteres con letras y números.
    // ^(?=.*[0-9]) -> Al menos un número
    // (?=.*[a-zA-Z]) -> Al menos una letra
    // .{8}$ -> Exactamente 8 caracteres de longitud
    private static final String PASSWORD_REGEX = "^(?=.*[0-9])(?=.*[a-zA-Z]).{8}$";
    
    private UsuarioDAO usuarioDAO;

    @Override
    public void init() throws ServletException {
        try {
            // Conectamos con el Pool de conexiones configurado en el servidor (JNDI)
            InitialContext ctx = new InitialContext();
            DataSource dataSource = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            usuarioDAO = new UsuarioDAO(dataSource);
        } catch (Exception e) {
            throw new ServletException("Error al conectar con la base de datos en RegistroServlet", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // Captura de datos del formulario de registro
        String dni = request.getParameter("dni");
        String correo = request.getParameter("correo");
        String contrasena = request.getParameter("contrasena");
        String contrasena2 = request.getParameter("contrasena2");

        // 1. VALIDACIÓN DE CAMPOS VACÍOS: Evita que entren nulos a la BD
        if (esVacio(dni) || esVacio(correo) || esVacio(contrasena) || esVacio(contrasena2)) {
            enviarError(request, response, "Todos los campos son obligatorios.");
            return;
        }

        // 2. VALIDACIÓN DE ROBUSTEZ: Comprueba que cumpla con la política de seguridad (Regex)
        if (!contrasena.matches(PASSWORD_REGEX)) {
            // Devolvemos los datos para que el usuario no tenga que reescribirlos
            request.setAttribute("dni", dni);
            request.setAttribute("correo", correo);
            enviarError(request, response, "La contraseña debe tener exactamente 8 caracteres, incluyendo letras y números.");
            return;
        }

        // 3. VALIDACIÓN DE COINCIDENCIA: Evita errores de escritura del usuario
        if (!contrasena.equals(contrasena2)) {
            request.setAttribute("dni", dni);
            request.setAttribute("correo", correo);
            enviarError(request, response, "Las contraseñas no coinciden.");
            return;
        }

        try {
            // 4. VERIFICACIÓN DE IDENTIDAD ÚNICA
            if (usuarioDAO.obtenerUsuarioPorDNI(dni) != null) {
                enviarError(request, response, "El DNI introducido ya se encuentra registrado.");
                return;
            }

            // 5. PREPARACIÓN DEL OBJETO USUARIO
            Usuario nuevo = new Usuario();
            nuevo.setDni(dni);
            nuevo.setCorreo(correo);
            nuevo.setContrasena(contrasena); 
            
            // Inicializamos el resto de campos de seguridad adaptativa a null.
            // Estos se configurarán en el primer inicio de sesión exitoso.
            nuevo.setIpRegistro(null);
            nuevo.setUbicacion(null);
            nuevo.setTotpSecret(null);

            // 6. PERSISTENCIA: Intentamos guardar en la base de datos
            boolean exito = usuarioDAO.registrarUsuario(nuevo);

            if (exito) {
                // Éxito: Redirigimos al login con un parámetro para mostrar un mensaje de confirmación
                response.sendRedirect("index.jsp?registro=ok");
            } else {
                enviarError(request, response, "Error técnico al guardar el usuario. Inténtelo más tarde.");
            }

        } catch (Exception e) {
            e.printStackTrace();
            enviarError(request, response, "Error en el servidor: " + e.getMessage());
        }
    }

    /**
     * Comprueba si una cadena es nula o solo contiene espacios.
     */
    private boolean esVacio(String s) {
        return s == null || s.trim().isEmpty();
    }

  
    private void enviarError(HttpServletRequest req, HttpServletResponse resp, String msj) 
            throws ServletException, IOException {
        req.setAttribute("error", msj);
        req.getRequestDispatcher("registro.jsp").forward(req, resp);
    }
}