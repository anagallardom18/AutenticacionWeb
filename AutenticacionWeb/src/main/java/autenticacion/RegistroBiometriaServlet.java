package autenticacion;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.*;
import java.util.Base64;
import com.google.gson.Gson;

@WebServlet("/RegistroBiometriaServlet")
public class RegistroBiometriaServlet extends HttpServlet {

    private final SecureRandom random = new SecureRandom();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String dni = req.getParameter("dni");
        if (dni == null || dni.isEmpty()) {
            resp.sendError(400, "Falta DNI");
            return;
        }

        //generar challenge
        byte[] challenge = new byte[32];
        random.nextBytes(challenge);
        String challengeB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);

        //generar userId
        byte[] userId = new byte[16];
        random.nextBytes(userId);
        String userIdB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(userId);

        //guardar en sesión
        HttpSession session = req.getSession();
        session.setAttribute("webauthn_registration_challenge", challengeB64);
        session.setAttribute("webauthn_registration_dni", dni);

        //preparar opciones para el navegador
        Map<String, Object> options = new HashMap<>();
        options.put("challenge", challengeB64);
        options.put("rp", Map.of("id", req.getServerName(), "name", "AutenticacionWeb"));
        options.put("user", Map.of("id", userIdB64, "name", dni, "displayName", dni));
        options.put("pubKeyCredParams", List.of(
                Map.of("type", "public-key", "alg", -7),   // ES256
                Map.of("type", "public-key", "alg", -257)  // RS256
        ));
        options.put("authenticatorSelection", Map.of("residentKey", "preferred", "userVerification", "required"));
        options.put("timeout", 60000);
        options.put("attestation", "none");
        options.put("excludeCredentials", List.of());

        //devolver JSON
        resp.setContentType("application/json");
        resp.getWriter().write(new Gson().toJson(options));
    }
}

        
      