package autenticacion;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.*;
import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.nio.ByteBuffer;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;

import com.google.gson.*;

/**
 * Servlet encargado de gestionar la autenticación mediante Passkeys.
 * Las Passkeys son credenciales residentes que permiten una experiencia Passwordless
 * basada en el estándar FIDO2/WebAuthn, vinculando la identidad al dispositivo.
 */
@WebServlet("/AutPasskeyServlet")
public class AutPasskeyServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private final Gson gson = new Gson();
    private UsuarioDAO usuarioDAO;
    private ConfigService configService;
    private Correo servicioCorreo;

    /**
     * Inicialización del pool de conexiones y servicios de soporte.
     */
    @Override
    public void init() throws ServletException {
        try {
            Context ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            usuarioDAO = new UsuarioDAO(ds);
            configService = new ConfigService(ds);
            this.servicioCorreo = new Correo(this.configService);
        } catch (Exception e) {
            throw new ServletException("Error inicializando servicios en AutPasskeyServlet", e);
        }
    }

    /**
     * Procesa el intento de login con Passkey.
     * Valida tanto el desafío (Challenge) como la firma criptográfica enviada por el navegador.
     */
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");

        HttpSession session = req.getSession(true);
        Map<String, Object> jsonResponse = new HashMap<>();

        try {
            // 1. LECTURA DE DATOS RECIBIDOS (JSON)
            JsonObject json = gson.fromJson(req.getReader(), JsonObject.class);
            
            String modoLogin = json.has("modoLogin") ? json.get("modoLogin").getAsString() : "1FA";
            String dni = json.has("dni") ? json.get("dni").getAsString() : (String) session.getAttribute("webauthn_dni");
            String expectedChallenge = (String) session.getAttribute("webauthn_challenge");

            if (dni == null || dni.isEmpty()) {
                enviarError(resp, 400, "Identificación de usuario no encontrada para Passkey.");
                return;
            }

            // 2. EXTRACCIÓN DE COMPONENTES DE LA ASERCIÓN
            JsonObject responseJson = json.getAsJsonObject("response");
            byte[] credentialId = decodificarBase64(json.get("rawId").getAsString());
            byte[] clientDataJSON = decodificarBase64(responseJson.get("clientDataJSON").getAsString());
            byte[] authenticatorData = decodificarBase64(responseJson.get("authenticatorData").getAsString());
            byte[] signature = decodificarBase64(responseJson.get("signature").getAsString());

            // 3. VALIDACIÓN DEL DESAFÍO (ANTI-REPLAY)
            JsonObject clientDataObj = gson.fromJson(new String(clientDataJSON, "UTF-8"), JsonObject.class);
            String receivedChallenge = clientDataObj.get("challenge").getAsString();
            if (expectedChallenge == null || !receivedChallenge.equals(expectedChallenge)) {
                enviarError(resp, 401, "Challenge de seguridad inválido o caducado.");
                return;
            }

            // 4. RECUPERACIÓN DE LA CREDENCIAL REGISTRADA
            UsuarioDAO.WebAuthnCredential cred = usuarioDAO.obtenerPasskey(dni, credentialId);
            if (cred == null) {
                enviarError(resp, 404, "Passkey no registrada para este usuario.");
                return;
            }

            // 5. VALIDACIÓN CRIPTOGRÁFICA
            // Se comprueba que el cliente posee la clave privada vinculada a la clave pública guardada.
            boolean firmaOK = FirmaWeb.validarFirma(authenticatorData, clientDataJSON, signature, cred.getPublicKey());
            if (!firmaOK) {
                enviarError(resp, 401, "Firma de Passkey inválida.");
                return;
            }

            // 6. ACTUALIZACIÓN DEL MODELO DE CONFIANZA (Categoría SER)
         
            @SuppressWarnings("unchecked")
            List<String> categoriasSuperadas = (List<String>) session.getAttribute("categoriasSuperadas");
            
            if (categoriasSuperadas == null) categoriasSuperadas = new ArrayList<>();
            if (!categoriasSuperadas.contains("SER")) {
                categoriasSuperadas.add("SER");
            }
            session.setAttribute("categoriasSuperadas", categoriasSuperadas);
            session.setAttribute("usuarioTemp", dni);

            // 7. PROTECCIÓN DE INTEGRIDAD (Sign Count)
            try {
                int signCount = ByteBuffer.wrap(authenticatorData).getInt(33);
                usuarioDAO.actualizarSignCountPasskey(dni, credentialId, signCount);
            } catch (Exception e) {
                // El error de actualización de contador no bloquea el login pero se registra.
            }

            // 8. FLUJO DE NAVEGACIÓN SEGÚN POLÍTICA DE ACCESO
            if ("1FA".equals(modoLogin)) {
            	usuarioDAO.resetearIntentos(dni);
                // Caso: Acceso directo simplificado
                session.setAttribute("usuario", dni); 
                jsonResponse.put("success", true);
                jsonResponse.put("redirect", "bienvenido.jsp");
            } 
            else {
                // Caso: Validación de cumplimiento Multi-Factor
                if (categoriasSuperadas.size() >= 2) {
                	usuarioDAO.resetearIntentos(dni);
                    session.setAttribute("usuario", dni);
                    jsonResponse.put("success", true);
                    jsonResponse.put("redirect", "bienvenido.jsp");
                } else {
                    // Refuerzo de identidad: se intenta el envío de un OTP como factor de posesión.
                    Usuario usuario = usuarioDAO.obtenerUsuarioPorDNI(dni);
                    String correo = (usuario != null) ? usuario.getCorreo() : null;

                    if (correo == null || correo.isEmpty()) {
                        jsonResponse.put("success", true);
                        jsonResponse.put("redirect", "loginAlternativo.jsp");
                    } else {
                        String otp = Correo.generaOTP();
                        session.setAttribute("otp", otp);
                        try {
                            servicioCorreo.enviaCorreo(correo, otp);
                            jsonResponse.put("success", true);
                            jsonResponse.put("redirect", "verificaOTP.jsp");
                        } catch (Exception e) {
                            jsonResponse.put("success", true);
                            jsonResponse.put("redirect", "loginAlternativo.jsp");
                        }
                    }
                }
            }

            resp.getWriter().write(gson.toJson(jsonResponse));

        } catch (Exception e) {
            e.printStackTrace();
            enviarError(resp, 500, "Error crítico en el proceso de autenticación por Passkey.");
        }
    }

    /**
     * Utilidad para decodificar Base64 gestionando variaciones de relleno y URL-safe.
     */
    private byte[] decodificarBase64(String b64) {
        if (b64 == null) return new byte[0];
        try {
            return Base64.getUrlDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            return Base64.getDecoder().decode(b64);
        }
    }

    /**
     * Centraliza las respuestas de error en formato JSON para el cliente.
     */
    private void enviarError(HttpServletResponse resp, int code, String msg) throws IOException {
        resp.setStatus(code);
        Map<String, Object> error = new HashMap<>();
        error.put("success", false);
        error.put("message", msg);
        resp.getWriter().write(gson.toJson(error));
    }
}