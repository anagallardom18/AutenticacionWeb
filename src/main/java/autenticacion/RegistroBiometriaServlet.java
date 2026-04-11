package autenticacion;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.*;
import java.nio.charset.StandardCharsets;
import com.google.gson.Gson;

/**
 * Servlet que prepara los parámetros para registrar un nuevo sensor biométrico.
 * Se encarga de la fase de "petición de registro" en el estándar WebAuthn.
 */
@WebServlet("/RegistroBiometriaServlet")
public class RegistroBiometriaServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private final SecureRandom random = new SecureRandom(); // Generador de aleatorios seguro para criptografía
    private final Gson gson = new Gson();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        // 1. CONTROL DE ACCESO: Solo usuarios que han iniciado sesión pueden registrar su biometría.
        // Verificamos que exista una sesión activa y que tenga el atributo "usuario" (DNI).
        HttpSession session = req.getSession(false);
        if (session == null || session.getAttribute("usuario") == null) {
            resp.sendError(401, "Debe iniciar sesión para registrar biometría.");
            return;
        }

        String dni = (String) session.getAttribute("usuario");

        // 2. GENERACIÓN DEL CHALLENGE (Reto de registro):
        // Creamos 32 bytes aleatorios. Esto evita ataques de interceptación (replay attacks).
        byte[] challenge = new byte[32];
        random.nextBytes(challenge);
        
        // El estándar WebAuthn exige Base64URL sin relleno (padding).
        String challengeB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);

        // 3. PERSISTENCIA TEMPORAL:
        // Guardamos el reto en la sesión. Cuando el usuario termine de poner su huella, 
        // el servidor comparará que el reto firmado coincida con este.
        session.setAttribute("webauthn_registration_challenge", challengeB64);

        // 4. CONSTRUCCIÓN DEL OBJETO DE OPCIONES (PublicKeyCredentialCreationOptions):
        Map<String, Object> options = new HashMap<>();
        
        // Reto único para esta operación
        options.put("challenge", challengeB64);
        
        // rp: El "Relying Party" (tu servidor). El navegador solo activará el sensor si el dominio coincide.
        options.put("rp", Map.of("id", req.getServerName(), "name", "Mi Aplicación"));
        
        // user: Identificamos al usuario. El ID debe ser el DNI convertido a bytes y luego a Base64URL.
        String userIdB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(dni.getBytes(StandardCharsets.UTF_8));
        options.put("user", Map.of("id", userIdB64, "name", dni, "displayName", dni));
        
        // pubKeyCredParams: Le decimos al navegador qué algoritmos de clave pública aceptamos.
        // -7 = ES256 (El estándar para móviles modernos), -257 = RS256.
        options.put("pubKeyCredParams", List.of(
                Map.of("type", "public-key", "alg", -7), 
                Map.of("type", "public-key", "alg", -257)
        ));
        
        // authenticatorSelection: CONFIGURACIÓN CRÍTICA
        options.put("authenticatorSelection", Map.of(
                // "platform" obliga a usar biometría local (Windows Hello, TouchID, FaceID)
                "authenticatorAttachment", "platform", 
                // Exigimos que el dispositivo verifique que el usuario es el dueño (PIN o biometría)
                "userVerification", "required"
        ));
        
        options.put("timeout", 60000); // El usuario tiene 1 minuto para poner el dedo/cara
        options.put("attestation", "none"); // No pedimos certificado de autenticidad del hardware

        // 5. RESPUESTA AL FRONTEND: Enviamos todo como JSON para que lo use navigator.credentials.create()
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.getWriter().write(gson.toJson(options));
    }
}