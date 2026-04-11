package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;
import javax.naming.InitialContext;
import javax.naming.Context;
import javax.sql.DataSource;
import java.io.IOException;
import org.json.JSONObject;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/*
 * Servlet para el inicio de sesión con contraseña
 * Implementa una lógica de autenticación adaptativa basada en riesgo y gestiona
 * la persistencia de los factores en la "mochila" del usuario durante la sesión.
 */
@WebServlet("/LoginServlet")
public class LoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private UsuarioDAO usuarioDAO;
    private ConfigService configService;
    private Correo servicioCorreo; 

    /**
     * Inicialización de los servicios de persistencia y configuración mediante JNDI.
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
            throw new ServletException("Error al inicializar servicios core", e);
        }
    }

    /**
     * Procesa las solicitudes de inicio de sesión gestionando el flujo MFA y el análisis de riesgo.
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

    	 //  Recolección de parámetros de entrada (Credenciales y Contexto)
        String dni = request.getParameter("dni");
        String contrasena = request.getParameter("contrasena");
        String modoLoginInput = request.getParameter("modoLogin"); 
        String latActual = request.getParameter("latitud");
        String lonActual = request.getParameter("longitud");

        HttpSession sesion = request.getSession(true);

        // Validación de campos
        if (esVacio(dni) || esVacio(contrasena)) {
            mostrarError(request, response, "Campos obligatorios incompletos.", dni, false, modoLoginInput);
            return;
        } 

     // VALIDACIÓN DE LOGIN Y BLOQUEO PERSISTENTE (BBDD)
        String resultadoLogin = usuarioDAO.validarLoginCompleto(dni, contrasena);

        // CASO A: El usuario ha puesto la contraseña CORRECTA
        if ("OK".equals(resultadoLogin)) {
            // Reseteamos aquí para que, aunque luego le pidamos OTP,
            // el contador de la base de datos ya haya vuelto a 0.
            usuarioDAO.resetearIntentos(dni);
            System.out.println("DEBUG: Contraseña correcta. Intentos reseteados para: " + dni);
        } 

        // CASO B: El usuario se ha equivocado (y no está bloqueado todavía)
        else if (resultadoLogin.startsWith("FALLO:")) {
            String intentosBBDD = resultadoLogin.split(":")[1];
            mostrarError(request, response, "Credenciales incorrectas (" + intentosBBDD + "/3).", dni, false, modoLoginInput);
            return; // Cortamos el flujo aquí
        }

        // CASO C: El usuario ha fallado 3 veces o ya estaba bloqueado
        else if ("BLOQUEADO".equals(resultadoLogin)) {
            // No reseteamos nada. Lo mandamos a la pantalla de bloqueo.
            mostrarError(request, response, "Acceso por contraseña bloqueado. Use un método alternativo.", dni, true, modoLoginInput);
            return; // Cortamos el flujo aquí
        }

        // CASO D: El usuario no existe
        else if ("NO_EXISTE".equals(resultadoLogin)) {
            mostrarError(request, response, "Usuario no encontrado.", dni, false, modoLoginInput);
            return;
        }

   
        Usuario usuario = usuarioDAO.obtenerUsuarioPorDNI(dni);
       
        // Actualizamos la "Mochila" de factores en la sesión
        @SuppressWarnings("unchecked")
        List<String> categoriasSuperadas = (List<String>) sesion.getAttribute("categoriasSuperadas");
        if (categoriasSuperadas == null) categoriasSuperadas = new ArrayList<>();
        
        if (!categoriasSuperadas.contains("SABER")) {
            categoriasSuperadas.add("SABER"); 
        }
        sesion.setAttribute("categoriasSuperadas", categoriasSuperadas);
        sesion.setAttribute("usuarioTemp", dni);

        // 4. Análisis de Riesgo Adaptativo (Contextualización de IP y GPS)
        String ipActual = getClientIp(request);
        boolean hayRiesgo = false;
        StringBuilder mensajeRiesgo = new StringBuilder();

        // 6.1. Validación de IP habitual
        if (esVacio(usuario.getIpPermitida())) {
            usuarioDAO.actualizarIpPermitida(dni, ipActual);
        } else if (!usuario.getIpPermitida().equals(ipActual)) {
            hayRiesgo = true; 
            mensajeRiesgo.append("Conexión desde IP inusual detectada. ");
        }

        // 6.2. Validación de Geolocalización (Distancia mediante fórmula de Haversine)
        if (!esVacio(latActual) && !esVacio(lonActual)) {
            String latHab = usuario.getLatitudHabitual();
            String lonHab = usuario.getLongitudHabitual();
            if (esVacio(latHab)) {
                usuarioDAO.actualizarUbicacionGPS(dni, latActual, lonActual);
            } else {
                double dist = calcularDistancia(Double.parseDouble(latActual), Double.parseDouble(lonActual),
                                              Double.parseDouble(latHab), Double.parseDouble(lonHab));
                if (dist > 50.0) { // Umbral de 50km
                    hayRiesgo = true;
                    mensajeRiesgo.append("Ubicación geográfica anómala detectada. ");
                }
            }
        }
        
     // 5. MOTOR DE DECISIÓN DE ACCESO
        if (categoriasSuperadas.size() >= 2 || ("1FA".equals(modoLoginInput) && !hayRiesgo)) {
            
            // Intentamos sacar el DNI de varios sitios por si uno falla
            String dniFinal = (dni != null && !dni.isEmpty()) ? dni : (String) sesion.getAttribute("usuarioTemp");

            if (dniFinal != null) {
                System.out.println("DEBUG: Reseteando intentos para DNI: " + dniFinal); // Mira esto en la consola
                usuarioDAO.resetearIntentos(dniFinal);
                System.out.println("DEBUG: Acceso concedido. Reset final para: " + dniFinal);
            } else {
                System.out.println("DEBUG: No se pudo resetear porque el DNI es NULL");
            }

            sesion.setAttribute("usuario", dniFinal);
            registrarGeolocalizacionIP(dniFinal, ipActual);
            response.sendRedirect("bienvenido.jsp");
            return;
        }

        // Escenario B: Desafío de Segundo Factor (2FA por Correo)
        String correo = usuario.getCorreo();
        if (!esVacio(correo)) {
            String otp = Correo.generaOTP();
            sesion.setAttribute("otp", otp);
            try {
                servicioCorreo.enviaCorreo(correo, otp);
                registrarGeolocalizacionIP(dni, ipActual);
                
                if (hayRiesgo) {
                    request.setAttribute("error", mensajeRiesgo.toString() + "Se requiere verificación por OTP.");
                }
                request.getRequestDispatcher("verificaOTP.jsp").forward(request, response);
                return; 
            } catch (Exception e) {
                mostrarError(request, response, "Fallo al enviar el código de seguridad.", dni, false, modoLoginInput);
                return;
            }
        } else {
            // Escenario C: Fallback a factores físicos (Biometría/Llaves)
            request.setAttribute("error", "Riesgo detectado. Requiere autenticación física (WebAuthn/FIDO2).");
            request.getRequestDispatcher("loginAlternativo.jsp").forward(request, response);
        }
    }

    /**
     * Centraliza la lógica de redirección de errores para mantener la consistencia del flujo.
     */
    private void mostrarError(HttpServletRequest req, HttpServletResponse resp, String msg, String dni, boolean bloqueo, String modo) 
            throws ServletException, IOException {
        req.setAttribute("error", msg);
        req.setAttribute("dniRecordado", dni);
        // Si hay bloqueo, mandamos a la página alternativa de seguridad
        String destino = bloqueo ? "loginAlternativo.jsp" : ("1FA".equals(modo) ? "login1fa.jsp" : "login.jsp");
        req.getRequestDispatcher(destino).forward(req, resp);
    }
    /**
     * Implementación del algoritmo Haversine para calcular la distancia entre dos puntos geográficos.
     */
    private double calcularDistancia(double lat1, double lon1, double lat2, double lon2) {
        double radioTierra = 6371; 
        double dLat = Math.toRadians(lat2 - lat1);
        double dLon = Math.toRadians(lon2 - lon1);
        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2) + 
                   Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2)) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
        return 2 * radioTierra * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    }

    private boolean esVacio(String s) { return s == null || s.trim().isEmpty(); }

    /**
     * Extrae la dirección IP real del cliente, considerando posibles proxies mediante el header X-Forwarded-For.
     */
    private String getClientIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        return (xf != null && !xf.isEmpty()) ? xf.split(",")[0] : request.getRemoteAddr();
    }

    /**
     * Proceso asíncrono para registrar la geolocalización basada en IP mediante API externa.
     */
    private void registrarGeolocalizacionIP(String dni, String ip) {
        new Thread(() -> {
            try {
                String urlStr = "http://ip-api.com/json/" + URLEncoder.encode(ip, StandardCharsets.UTF_8);
                URL url = URI.create(urlStr).toURL();
                HttpURLConnection con = (HttpURLConnection) url.openConnection();
                con.setConnectTimeout(3000);
                try (InputStream in = con.getInputStream()) {
                    JSONObject json = new JSONObject(new String(in.readAllBytes(), StandardCharsets.UTF_8));
                    usuarioDAO.registrarAccesoIP(dni, ip, json.optString("country"), json.optString("city"));
                }
            } catch (Exception ignored) {} 
        }).start();
    }
}