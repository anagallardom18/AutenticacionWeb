package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;
import java.io.*;
import java.util.Base64;
import com.google.gson.*;
import java.sql.*; 

@WebServlet("/AutFido2Servlet")
public class AutFido2Servlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private Gson gson = new Gson();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        
        try {
            JsonObject body = gson.fromJson(req.getReader(), JsonObject.class);

            //leer datos de la credencial FIDO2
            String rawIdB64 = body.get("rawId").getAsString();
            String clientDataJSONB64 = body.getAsJsonObject("response").get("clientDataJSON").getAsString();
            String dni = body.has("dni") ? body.get("dni").getAsString() : null;

            if (dni == null) {
                resp.sendError(400, "Falta el dni");
                return;
            }

            HttpSession session = req.getSession(false);
            if (session == null) {
                resp.sendError(400, "Sesión expirada");
                return;
            }

            //validar challenge y DNI de la Sesión
            String expectedChallenge = (String) session.getAttribute("webauthn_challenge");
            String expectedDni = (String) session.getAttribute("webauthn_dni");
            
            if (expectedChallenge == null || !dni.equals(expectedDni)) {
                resp.sendError(401, "Falta hallenge o el dni no coincide");
                return;
            }
            
            rawIdB64 = rawIdB64.replace('+', '-').replace('/', '_');

         
            byte[] rawId = Base64.getUrlDecoder().decode(rawIdB64);
        
            byte[] clientDataJSON = Base64.getUrlDecoder().decode(clientDataJSONB64);

            //verificación del challenge 
            JsonObject clientDataObj = gson.fromJson(new String(clientDataJSON, "UTF-8"), JsonObject.class);
            String receivedChallenge = clientDataObj.get("challenge").getAsString();
            
            if (!receivedChallenge.equals(expectedChallenge)) {
                 resp.sendError(401, "Challenge no coincide con el de la sesión.");
                 return;
            }

            //obtener credencial FIDO2 de la base de datos
            UsuarioDAO.WebAuthnCredential credencial = UsuarioDAO.obtenerCredencialFido2(dni, rawId);

            if (credencial == null) {
                resp.sendError(401, "Credencial FIDO2 no encontrada.");
                return;
            }
            
            // Simular la actualización del Sign Count
            long signCountStored = credencial.getSignCount();
            long newSignCount = signCountStored + 1; 
            
            //actualizar el contador de firmas en la BD
            UsuarioDAO.actualizarSignCountFido2(dni, rawId, newSignCount);


            //si exito:
            
            Usuario usuario = UsuarioDAO.obtenerUsuarioPorDNI(dni);
            if (usuario == null) {
                resp.sendError(500, "Usuario no encontrado después de la verificación FIDO2.");
                return;
            }
            
            //generar OTP y continuar el flujo de 2FA
            String otp = Correo.generaOTP();
            session.setAttribute("otp", otp);
            session.setAttribute("usuarioTemp", dni); 

            String correo = usuario.getCorreo();
            if (correo == null) {
                resp.sendError(500, "Correo del usuario no encontrado");
                return;
            }

  
            Correo.enviaCorreo(correo, otp);

            resp.setContentType("application/json");
            resp.getWriter().write("{\"success\":true}");

        } catch (SQLException e) { 
            
            e.printStackTrace();
            resp.sendError(500, "Eror de base de datos: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            resp.sendError(500, "Error de autenticacion: " + e.getMessage());
        }
    }
}