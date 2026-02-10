package autenticacion;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;

@WebServlet("/RegistroPasskeyServlet")
public class RegistroPasskeyServlet extends HttpServlet {

    private final SecureRandom random = new SecureRandom();
    private final Gson gson = new Gson();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {

        HttpSession session = req.getSession(false);
        if (session == null || session.getAttribute("usuario") == null) {
            resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        String dni = (String) session.getAttribute("usuario");

        //generar challenge único
        byte[] challenge = new byte[32];
        random.nextBytes(challenge);
        String challengeB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);

        //guardar en sesión
        session.setAttribute("passkey_challenge", challengeB64);
        session.setAttribute("passkey_dni", dni);

        //construir opciones WebAuthn para registro
        Map<String, Object> options = new HashMap<>();
        options.put("challenge", challengeB64);
        options.put("rp", Map.of(
                "id", req.getServerName(),
                "name", "AutenticacionWeb"
        ));
        options.put("user", Map.of(
                "id", Base64.getUrlEncoder().withoutPadding().encodeToString(dni.getBytes()),
                "name", dni,
                "displayName", dni
        ));
        options.put("pubKeyCredParams", List.of(
                Map.of("type", "public-key", "alg", -7),
                Map.of("type", "public-key", "alg", -257)
        ));
        options.put("timeout", 60000);
        options.put("attestation", "none");
        options.put("authenticatorSelection", Map.of(
                "residentKey", "required",
                "userVerification", "required"
        ));

        //evitar cache
        resp.setHeader("Cache-Control", "no-store");
        resp.setHeader("Pragma", "no-cache");

        //enviar JSON al navegador
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.getWriter().write(gson.toJson(options));
    }
}
