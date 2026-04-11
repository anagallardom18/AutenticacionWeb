package autenticacion;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.*;
import java.nio.charset.StandardCharsets;
import com.google.gson.Gson;

/**
 * Servlet encargado de iniciar el registro de una llave física FIDO2 (Security Key).
 */
@WebServlet("/RegistroFido2Servlet")
public class RegistroFido2Servlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private final SecureRandom random = new SecureRandom();
    private final Gson gson = new Gson();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        // 1. VERIFICACIÓN DE IDENTIDAD: Solo permitimos el registro si el usuario ya está autenticado
        HttpSession session = req.getSession(false);
        if (session == null || session.getAttribute("usuario") == null) {
            resp.sendError(401, "No autorizado: Inicie sesión primero.");
            return;
        }

        String dni = (String) session.getAttribute("usuario");

        // 2. GENERACIÓN DEL RETO (CHALLENGE):
        // Creamos un valor aleatorio de 32 bytes para asegurar que la operación sea única
        // y evitar ataques de repetición (Replay Attacks).
        byte[] challenge = new byte[32];
        random.nextBytes(challenge);
        
        // El reto debe viajar al cliente en formato Base64URL sin relleno (padding)
        String challengeB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);

        // 3. SEGURIDAD TEMPORAL: Guardamos el reto en la sesión para validarlo en el siguiente paso
        session.setAttribute("webauthn_registration_challenge", challengeB64);

        // 4. CONFIGURACIÓN DEL OBJETO DE REGISTRO (WebAuthn Options):
        Map<String, Object> options = new HashMap<>();
        
        // Desafío aleatorio que la llave física deberá firmar
        options.put("challenge", challengeB64);
        
        // rp: "Relying Party". El ID debe ser el dominio
        options.put("rp", Map.of("id", req.getServerName(), "name", "Seguridad FIDO2"));
        
        // user: Información del usuario para que la llave pueda guardarla internamente
        String userIdB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(dni.getBytes(StandardCharsets.UTF_8));
        options.put("user", Map.of("id", userIdB64, "name", dni, "displayName", dni));
        
        // pubKeyCredParams: Listado de algoritmos criptográficos que el servidor sabe validar
        // -7: ECDSA con curva P-256 (estándar FIDO)
        // -257: RSA con SHA-256
        options.put("pubKeyCredParams", List.of(
                Map.of("type", "public-key", "alg", -7),
                Map.of("type", "public-key", "alg", -257)
        ));
        
        // 5. SELECCIÓN DEL AUTENTICADOR (LLAVE FÍSICA):
        options.put("authenticatorSelection", Map.of(
                // "cross-platform" indica que queremos dispositivos que puedan moverse entre equipos (USB/NFC)
                "authenticatorAttachment", "cross-platform", 
                // "required" obliga a que la llave tenga un PIN o protección biométrica propia
                "userVerification", "required"
        ));
        
        options.put("timeout", 60000); // 1 minuto de espera para que el usuario conecte y toque la llave
        options.put("attestation", "none"); // No solicitamos datos de fabricación de la llave por privacidad

        // 6. RESPUESTA AL CLIENTE: Enviamos el JSON que consumirá el JavaScript 'navigator.credentials.create'
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.getWriter().write(gson.toJson(options));
    }
}