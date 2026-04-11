package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

import javax.naming.InitialContext;
import javax.sql.DataSource;

import com.google.gson.Gson;

/**
 * Servlet que prepara las opciones para la autenticación mediante llaves FIDO2.
 * Genera el desafío criptográfico necesario para evitar ataques de replicación.
 */
@WebServlet("/OpcionesFido2Servlet")
public class OpcionesFido2Servlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private SecureRandom random; // Generador de números aleatorios seguro para criptografía
    private Gson gson;
    private UsuarioDAO usuarioDAO;

    @Override
    public void init() throws ServletException {
        try {
            random = new SecureRandom();
            gson = new Gson();
            // Inicialización de la conexión a la BD mediante JNDI
            InitialContext ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            usuarioDAO = new UsuarioDAO(ds);
        } catch (Exception e) { 
            throw new ServletException("Error al inicializar recursos en OpcionesFido2", e); 
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // Obtenemos el DNI del usuario para saber de quién buscar las llaves
        String dni = req.getParameter("dni");
        if (dni == null || dni.isBlank()) {
            enviarError(resp, 400, "Falta el DNI");
            return;
        }

        // 1. CREACIÓN DEL CHALLENGE:
        // Se generan 32 bytes aleatorios que el dispositivo físico deberá "firmar"
        byte[] challenge = new byte[32];
        random.nextBytes(challenge);
        
        // Se codifica en Base64URL (sin relleno) según exige el estándar WebAuthn
        String challengeB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);

        // 2. ALMACENAMIENTO EN SESIÓN:
        // Guardamos el reto en la sesión para poder validarlo cuando el cliente responda
        HttpSession session = req.getSession(true);
        session.setAttribute("webauthn_challenge", challengeB64);
        session.setAttribute("webauthn_dni", dni);

        // 3. RECUPERACIÓN DE CREDENCIALES:
        // Buscamos en la BD las llaves FIDO2 registradas previamente por este DNI
        List<Map<String, Object>> allowCredentials = usuarioDAO.listarFido2(dni);

        // 4. CONFIGURACIÓN DEL OBJETO DE RESPUESTA:
        Map<String, Object> options = new HashMap<>();
        options.put("challenge", challengeB64);
        options.put("timeout", 60000); // Tiempo límite de 1 minuto para realizar la acción física
        options.put("userVerification", "preferred"); // Indica si se prefiere PIN/Biometría en la llave
        options.put("rpId", req.getServerName()); // El ID del "Relying Party" (nombre del servidor)

        // Configuración del servidor (RP)
        Map<String, Object> rp = new HashMap<>();
        rp.put("id", req.getServerName());
        rp.put("name", "Autenticacion FIDO2");
        options.put("rp", rp);

        // Configuración del usuario
        Map<String, Object> user = new HashMap<>();
        user.put("id", Base64.getUrlEncoder().withoutPadding().encodeToString(dni.getBytes(StandardCharsets.UTF_8)));
        user.put("name", dni);
        user.put("displayName", dni);
        options.put("user", user);

        // Definición de algoritmos criptográficos soportados (-7 = ES256, -257 = RS256)
        options.put("pubKeyCredParams", List.of(
            Map.of("type", "public-key", "alg", -7),
            Map.of("type", "public-key", "alg", -257)
        ));

        // 5. LISTA DE LLAVES PERMITIDAS:
        // El navegador solo intentará activar las llaves que coincidan con estos IDs
        options.put("allowCredentials", (allowCredentials != null) ? allowCredentials : new ArrayList<>());

        // 6. RESPUESTA AL CLIENTE (JSON):
        // Forzamos a que no se guarde en caché para que el reto sea siempre nuevo
        resp.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.getWriter().write(gson.toJson(options));
    }

  
    private void enviarError(HttpServletResponse resp, int code, String msg) throws IOException {
        resp.setStatus(code);
        resp.setContentType("application/json");
        resp.getWriter().write("{\"error\": \"" + msg + "\"}");
    }
}