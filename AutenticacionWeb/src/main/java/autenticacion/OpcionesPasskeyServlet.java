package autenticacion;

import jakarta.servlet.ServletException;
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

@WebServlet("/OpcionesPasskeyServlet")
public class OpcionesPasskeyServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private final SecureRandom random = new SecureRandom();
    private final Gson gson = new Gson();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        String dni = req.getParameter("dni");

        if (dni == null || dni.isBlank()) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "Falta el DNI");
            return;
        }

        //generar challenge
        byte[] challenge = new byte[32];
        random.nextBytes(challenge);

        String challengeB64 = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(challenge);

        //guardar en sesión
        HttpSession session = req.getSession(true);
        session.setAttribute("webauthn_challenge", challengeB64);
        session.setAttribute("webauthn_dni", dni);

        //obtener credenciales Passkey (si existen)
        List<Map<String, Object>> allowCredentials;
        try {
            allowCredentials = UsuarioDAO.obtenerCredencialesPasskey(dni);
        } catch (Exception e) {
            e.printStackTrace();
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Error al obtener credenciales Passkey");
            return;
        }

        //construir opciones WebAuthn
        Map<String, Object> options = new HashMap<>();
        options.put("challenge", challengeB64);

        //información del Relying Party
        Map<String, Object> rp = new HashMap<>();
        rp.put("id", req.getServerName());
        rp.put("name", "AutenticacionWeb");
        options.put("rp", rp);

        //información del usuario
        Map<String, Object> user = new HashMap<>();
        user.put("id", Base64.getUrlEncoder().encodeToString(dni.getBytes()));
        user.put("name", dni);
        user.put("displayName", dni);
        options.put("user", user);

        //parametros de la clave publica
        options.put("pubKeyCredParams", List.of(
                Map.of("type", "public-key", "alg", -7),    
                Map.of("type", "public-key", "alg", -257)   
        ));

        options.put("timeout", 60000);
        options.put("userVerification", "required");

        //allowCredentials solo si hay credenciales registradas
        if (!allowCredentials.isEmpty()) {
            options.put("allowCredentials", allowCredentials);
        }

        //evitar cache del navegador
        resp.setHeader("Cache-Control", "no-store");
        resp.setHeader("Pragma", "no-cache");

        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.getWriter().write(gson.toJson(options));
    }
}
