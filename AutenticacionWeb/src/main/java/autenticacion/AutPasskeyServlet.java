package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;
import java.io.*;
import java.util.Base64;
import com.google.gson.*;
import java.sql.*; 

@WebServlet("/AutPasskeyServlet")
public class AutPasskeyServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private Gson gson = new Gson();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        
        try {
            JsonObject body = gson.fromJson(req.getReader(), JsonObject.class);

            //leer datos de la credencial Passkey
            String rawIdB64 = body.get("rawId").getAsString();
            JsonObject responseJson = body.getAsJsonObject("response");
            String clientDataJSONB64 = responseJson.get("clientDataJSON").getAsString();
            String dni = (body.has("dni") ? body.get("dni").getAsString() : null);

            if (dni == null) {
                resp.sendError(400, "Falta el DNI");
                return;
            }

            HttpSession session = req.getSession(false);
            if (session == null) {
                resp.sendError(400, "Sesión expirada");
                return;
            }

            //validar challenge y DNI de la sesión
            String expectedChallenge = (String) session.getAttribute("webauthn_challenge");
            String expectedDni = (String) session.getAttribute("webauthn_dni");
            
            if (expectedChallenge == null || !dni.equals(expectedDni)) {
                resp.sendError(401, "Challenge faltante o DNI no coincide");
                return;
            }

            //decodificar Base64URL
            rawIdB64 = rawIdB64.replace('-', '+').replace('_', '/');
            byte[] rawId = Base64.getDecoder().decode(rawIdB64);
            byte[] clientDataJSON = Base64.getDecoder().decode(clientDataJSONB64);

            //verificar challenge recibido
            JsonObject clientDataObj = gson.fromJson(new String(clientDataJSON, "UTF-8"), JsonObject.class);
            String receivedChallenge = clientDataObj.get("challenge").getAsString();
            
            if (!receivedChallenge.equals(expectedChallenge)) {
                resp.sendError(401, "Challenge no coincide con la sesión.");
                return;
            }

            //obtener credencial Passkey desde BD
            UsuarioDAO.WebAuthnCredential credencial = UsuarioDAO.obtenerCredencialPasskey(dni, rawId);

            if (credencial == null) {
                resp.sendError(401, "Credencial Passkey no registrada.");
                return;
            }

            //actualizar sign_count 
            long signCountStored = credencial.getSignCount();
            long newSignCount = signCountStored + 1;
            UsuarioDAO.actualizarSignCountPasskey(dni, rawId, newSignCount);

            //flujo de éxito
            Usuario usuario = UsuarioDAO.obtenerUsuarioPorDNI(dni);
            if (usuario == null) {
                resp.sendError(500, "Usuario no encontrado tras la verificación Passkey.");
                return;
            }

            //generar OTP y continuar flujo 2FA
            String otp = Correo.generaOTP();
            session.setAttribute("otp", otp);
            session.setAttribute("usuarioTemp", dni);

            String correo = usuario.getCorreo();
            if (correo == null) {
                resp.sendError(500, "Correo del usuario no encontrado");
                return;
            }

            Correo.enviaCorreo(correo, otp);

            //
            resp.setContentType("application/json");
            resp.getWriter().write("{\"success\":true}");

        } catch (SQLException e) { 
            e.printStackTrace();
            resp.sendError(500, "Error DB: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            resp.sendError(500, "Error en la autenticación: " + e.getMessage());
        }
    }
}
