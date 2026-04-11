package autenticacion;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

import javax.naming.InitialContext;
import javax.sql.DataSource;

import com.google.gson.Gson;

/**
 * Servlet que genera el reto (challenge) para iniciar sesión con Passkeys.
 * Las Passkeys son credenciales que pueden estar en varios dispositivos.
 */
@WebServlet("/OpcionesPasskeyServlet")
public class OpcionesPasskeyServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private SecureRandom random; // Generador para el desafío criptográfico
    private Gson gson;
    private UsuarioDAO usuarioDAO;

    @Override
    public void init() throws ServletException {
        try {
            random = new SecureRandom();
            gson = new Gson();
            // Localización del recurso de Base de Datos
            InitialContext ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            usuarioDAO = new UsuarioDAO(ds);
        } catch (Exception e) { 
            throw new ServletException("Error inicializando OpcionesPasskey", e); 
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // Obtenemos el DNI del usuario interesado en loguearse
        String dni = req.getParameter("dni");
        if (dni == null || dni.isBlank()) {
            enviarError(resp, 400, "Falta el DNI");
            return;
        }

        // 1. GENERACIÓN DEL CHALLENGE:
        // Creamos un array de 32 bytes aleatorios. 
        // Cada intento de login debe tener un challenge distinto para evitar ataques de repetición.
        byte[] challenge = new byte[32];
        random.nextBytes(challenge);
        
        // Codificamos en Base64URL sin relleno (padding) para cumplir el estándar WebAuthn
        String challengeB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);

        // 2. PERSISTENCIA EN SESIÓN:
        // El servidor guarda el reto y el DNI en la sesión HTTP para validarlos 
        // cuando el navegador envíe la respuesta firmada.
        HttpSession session = req.getSession(true);
        session.setAttribute("webauthn_challenge", challengeB64);
        session.setAttribute("webauthn_dni", dni);

        // 3. CONSULTA DE CREDENCIALES EXISTENTES:
        // Buscamos en la tabla de passkeys si este DNI ya tiene llaves registradas.
        List<Map<String, Object>> allowCredentials = usuarioDAO.listarPasskey(dni);

        // 4. CONSTRUCCIÓN DE LAS OPCIONES DE AUTENTICACIÓN:
        Map<String, Object> options = new HashMap<>();
        options.put("challenge", challengeB64);
        options.put("timeout", 60000); // El usuario tiene 60 segundos para interactuar
        
        // userVerification = "required": Obliga a que el usuario se valide físicamente (Huella/Cara/PIN)
        // ante su dispositivo antes de que este firme el challenge.
        options.put("userVerification", "required"); 
        
        options.put("rpId", req.getServerName()); // ID del servidor (Dominio)

        // Configuración de la Entidad que Confía (Relying Party)
        Map<String, Object> rp = new HashMap<>();
        rp.put("id", req.getServerName());
        rp.put("name", "Autenticacion Passkey");
        options.put("rp", rp);

        // Configuración del Usuario (ID único del usuario en formato B64)
        Map<String, Object> user = new HashMap<>();
        user.put("id", Base64.getUrlEncoder().withoutPadding().encodeToString(dni.getBytes(StandardCharsets.UTF_8)));
        user.put("name", dni);
        user.put("displayName", dni);
        options.put("user", user);

        // Algoritmos permitidos (ES256 y RS256 son los más comunes)
        options.put("pubKeyCredParams", List.of(
            Map.of("type", "public-key", "alg", -7),
            Map.of("type", "public-key", "alg", -257)
        ));

        // 5. ASIGNACIÓN DE LLAVES PERMITIDAS:
        // Enviamos la lista de IDs de Passkeys que el servidor reconocerá.
        options.put("allowCredentials", (allowCredentials != null) ? allowCredentials : new ArrayList<>());

        // 6. RESPUESTA AL CLIENTE:
        // Se envía el JSON para que el JavaScript frontal invoque a navigator.credentials.get()
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