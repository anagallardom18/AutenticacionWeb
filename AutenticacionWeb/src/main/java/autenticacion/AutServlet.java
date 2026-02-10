package autenticacion;

import jakarta.servlet.ServletException;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Base64;
import org.json.JSONObject;

@WebServlet("/AutServlet")
public class AutServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        HttpSession session = req.getSession();

        //recuperar dni de la sesión
        String dni = (String) session.getAttribute("webauthn_dni");
        if (dni == null) {
            resp.sendError(400, "Session expirada");
            return;
        }

        //leer JSON de WebAuthn desde el navegador
        StringBuilder sb = new StringBuilder();
        BufferedReader reader = req.getReader();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }

        JSONObject json = new JSONObject(sb.toString());
        String credentialIdB64 = json.getString("rawId");
        byte[] credentialId = Base64.getDecoder().decode(credentialIdB64);

        JSONObject responseJson = json.getJSONObject("response");
        byte[] clientDataJSON = Base64.getDecoder().decode(responseJson.getString("clientDataJSON"));
        byte[] authenticatorData = Base64.getDecoder().decode(responseJson.getString("authenticatorData"));
        byte[] signature = Base64.getDecoder().decode(responseJson.getString("signature"));

        //recuperar challenge de sesión
        String challengeStored = (String) session.getAttribute("webauthn_challenge");
        if (challengeStored == null) {
            resp.sendError(400, "Session expired");
            return;
        }

        //obtener credencial desde DAO
        UsuarioDAO.WebAuthnCredential cred = UsuarioDAO.obtenerCredencial(dni, credentialId);
        if (cred == null) {
            resp.setContentType("application/json");
            resp.getWriter().write("{\"success\":false, \"message\": \"Credencial no registrada\"}");
            return;
        }

        //validar firma WebAuthn
        boolean firmaOK = FirmaWeb.validarFirma(authenticatorData, clientDataJSON, signature, cred.getPublicKey());
        if (!firmaOK) {
            resp.setContentType("application/json");
            resp.getWriter().write("{\"success\":false, \"message\": \"Firma incorrecta\"}");
            return;
        }

        //actualizar signCount
        long newCount;
        try {
            PublicKeyExtractor.AttestationResult parsed = PublicKeyExtractor.parseAuthenticatorData(authenticatorData);
            newCount = parsed.getSignCount();
            UsuarioDAO.actualizarSignCount(dni, credentialId, newCount);
        } catch (Exception e) {
            e.printStackTrace();
            resp.sendError(500, "Error al actualizar sign_count");
            return;
        }

        //generar OTP y enviarlo por correo
        String otp = Correo.generaOTP();
        session.setAttribute("otp", otp);
        session.setAttribute("usuarioTemp", dni);

        Usuario usuario = UsuarioDAO.obtenerUsuarioPorDNI(dni);
        if (usuario != null && usuario.getCorreo() != null) {
            Correo.enviaCorreo(usuario.getCorreo(), otp);
        } else {
            resp.sendError(500, "Error al obtener correo del usuario");
            return;
        }

        //
        resp.setContentType("application/json");
        resp.getWriter().write("{\"success\":true}");
    }
}
