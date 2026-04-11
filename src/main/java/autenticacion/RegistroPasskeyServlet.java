package autenticacion;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.*;
import java.nio.charset.StandardCharsets;
import com.google.gson.Gson;

/**
 * Servlet el registro de una Passkey 
 */
@WebServlet("/RegistroPasskeyServlet")
public class RegistroPasskeyServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private final SecureRandom random = new SecureRandom(); 
    private final Gson gson = new Gson();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        // 1. CONTROL DE SESIÓN: El usuario debe estar autenticado para poder vincular una Passkey a su cuenta.
        HttpSession session = req.getSession(false);
        if (session == null || session.getAttribute("usuario") == null) {
            resp.sendError(401, "Sesión requerida: Inicie sesión para añadir una Passkey.");
            return;
        }

        String dni = (String) session.getAttribute("usuario");

        // 2. GENERACIÓN DEL CHALLENGE (RETO):
        // Creamos 32 bytes aleatorios. 
        byte[] challenge = new byte[32];
        random.nextBytes(challenge);
        
        // Codificación Base64URL (URL-Safe y sin padding) requerida por el estándar WebAuthn.
        String challengeB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);

        // 3. PERSISTENCIA TEMPORAL: Guardamos el reto para validarlo en el servlet de guardado.
        session.setAttribute("webauthn_registration_challenge", challengeB64);

        // 4. CONFIGURACIÓN DE LAS OPCIONES DE CREACIÓN (PublicKeyCredentialCreationOptions):
        Map<String, Object> options = new HashMap<>();
        options.put("challenge", challengeB64);
        
        // rp: Relying Party. El id debe ser el dominio para prevenir Phishing.
        options.put("rp", Map.of("id", req.getServerName(), "name", "Acceso Passkey"));
        
        // user: Información del usuario que la Passkey guardará internamente en el dispositivo.
        String userIdB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(dni.getBytes(StandardCharsets.UTF_8));
        options.put("user", Map.of("id", userIdB64, "name", dni, "displayName", dni));
        
        // pubKeyCredParams: Algoritmos criptográficos aceptados (-7: ES256, -257: RS256).
        options.put("pubKeyCredParams", List.of(
                Map.of("type", "public-key", "alg", -7),
                Map.of("type", "public-key", "alg", -257)
        ));
        
        // 5. CONFIGURACIÓN ESPECÍFICA DE PASSKEY (Resident Keys):
        // Esta es la parte que diferencia a una Passkey de una llave FIDO2 simple.
        options.put("authenticatorSelection", Map.of(
                // residentKey: 'required' asegura que la credencial se guarde en el dispositivo 
                // permitiendo el flujo "usernameless" (login sin escribir el nombre de usuario).
                "residentKey", "required", 
                "requireResidentKey", true,
                // userVerification: 'required' obliga al uso de PIN o Biometría del dispositivo.
                "userVerification", "required"
        ));
        
        options.put("timeout", 60000); // 1 minuto para completar el proceso
        options.put("attestation", "none"); // Por privacidad, no pedimos datos del fabricante del hardware

        // 6. RESPUESTA AL CLIENTE: El JSON se enviará al frontend para invocar la API del navegador.
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.getWriter().write(gson.toJson(options));
    }
}