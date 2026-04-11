package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.*;
import javax.naming.InitialContext;
import javax.sql.DataSource;
import com.google.gson.Gson;
import java.nio.charset.StandardCharsets;

/**
 * Servlet que genera el "Challenge" (Reto) para la autenticación biométrica.
 * Es el primer paso del login con Huella/FIDO2/Passkey.
 */
@WebServlet("/OpcionesBiometriaServlet")
public class OpcionesBiometriaServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private SecureRandom random; // Generador de números aleatorios criptográficamente
    private Gson gson;
    private UsuarioDAO usuarioDAO;

    @Override
    public void init() throws ServletException {
        try {
            random = new SecureRandom();
            gson = new Gson();
            // Conexión a la base de datos mediante el Pool JNDI
            InitialContext ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            usuarioDAO = new UsuarioDAO(ds);
        } catch (Exception e) { 
            throw new ServletException("Error al inicializar OpcionesBiometria", e); 
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String dni = req.getParameter("dni");
        
        // Necesitamos el DNI para saber que llaves buscar en la base de datos
        if (dni == null || dni.isBlank()) {
            enviarError(resp, 400, "DNI requerido");
            return;
        }

        // 1. GENERACIÓN DEL CHALLENGE:
        // Creamos 32 bytes aleatorios. Esto garantiza que cada intento de login sea único.
        byte[] challengeBytes = new byte[32];
        random.nextBytes(challengeBytes);
        
        // Lo codificamos en Base64URL (estándar WebAuthn) para enviarlo al JavaScript del navegador
        String challengeB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes);

        // 2. PERSISTENCIA TEMPORAL:
        // Guardamos el reto en la sesión del servidor para verificarlo más tarde cuando el usuario responda.
        HttpSession session = req.getSession(true);
        session.setAttribute("webauthn_challenge", challengeB64);
        session.setAttribute("webauthn_dni", dni);

        // 3. RECUPERACIÓN DE CREDENCIALES REGISTRADAS:
        // Consultamos al DAO todas las llaves (biometría/FIDO2) que este usuario ya tiene dadas de alta.
        List<Map<String, Object>> allowCreds = usuarioDAO.listarBiometria(dni);

        // 4. CONSTRUCCIÓN DEL OBJETO DE OPCIONES (PublicKeyCredentialRequestOptions):
        Map<String, Object> options = new HashMap<>();
        options.put("challenge", challengeB64);
        options.put("timeout", 60000); // El usuario tiene 60 segundos para poner la huella
        options.put("userVerification", "preferred"); // "preferred" permite usar PIN o Biometría
        
        options.put("rpId", req.getServerName());

        // Información del Relying Party (El servidor que confía en la llave)
        Map<String, Object> rp = new HashMap<>();
        rp.put("id", req.getServerName());
        rp.put("name", "Autenticacion Biometrica");
        options.put("rp", rp);

        // Información del usuario convertido a formato WebAuthn
        Map<String, Object> user = new HashMap<>();
        user.put("id", Base64.getUrlEncoder().withoutPadding().encodeToString(dni.getBytes(StandardCharsets.UTF_8)));
        user.put("name", dni);
        user.put("displayName", dni);
        options.put("user", user);

        // pubKeyCredParams: Algoritmos aceptados (-7 es ES256, -257 es RS256)
        options.put("pubKeyCredParams", List.of(
            Map.of("type", "public-key", "alg", -7),
            Map.of("type", "public-key", "alg", -257)
        ));

        // 5. FILTRADO: Le decimos al navegador qué llaves específicas puede usar para este usuario
        options.put("allowCredentials", (allowCreds != null) ? allowCreds : new ArrayList<>());

        // 6. RESPUESTA AL CLIENTE:
        // Evitamos que el navegador guarde en caché esta respuesta (el reto debe ser siempre nuevo)
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