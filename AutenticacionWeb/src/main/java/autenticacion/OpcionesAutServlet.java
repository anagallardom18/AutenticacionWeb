package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;
import java.io.*;
import java.util.*;
import java.util.Base64;
import java.security.SecureRandom;

import com.google.gson.Gson;

@WebServlet("/OpcionesAutServlet")
public class OpcionesAutServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private SecureRandom random = new SecureRandom();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String dni = req.getParameter("dni");
        if (dni == null || dni.isEmpty()) {
            resp.sendError(400, "Falta el DNI");
            return;
        }

        //genera challenge
        byte[] challenge = new byte[32];
        random.nextBytes(challenge);
        String challengeB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);

        //guardar en sesión para validar después
        HttpSession session = req.getSession();
        session.setAttribute("webauthn_challenge", challengeB64);
        session.setAttribute("webauthn_dni", dni);

        //recuperar allowCredentials desde DAO
        List<Map<String, Object>> allowCreds;
        try {
            allowCreds = UsuarioDAO.obtenerCredenciales(dni);
        } 
        catch (Exception e) { 
            e.printStackTrace();
            resp.sendError(500, "DB error");
            return;
        }

        Map<String,Object> options = new HashMap<>();
        options.put("challenge", challengeB64);
        options.put("rpId", req.getServerName());
        options.put("timeout", 60000);
        options.put("userVerification", "preferred");
        options.put("allowCredentials", allowCreds);

        //enviar JSON al cliente
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.getWriter().write(new Gson().toJson(options));
    }
}
