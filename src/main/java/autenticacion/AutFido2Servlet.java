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
 * Servlet encargado de la autenticación mediante llaves físicas de seguridad (FIDO2).
 * Gestiona el desafío de seguridad (Challenge) y verifica la posesión del hardware
 * mediante la validación de firmas criptográficas.
 */
@WebServlet("/AutFido2Servlet")
public class AutFido2Servlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private final Gson gson = new Gson();
    private UsuarioDAO usuarioDAO;
    private ConfigService configService;
    private Correo servicioCorreo;

    /**
     * Inicializa los servicios necesarios para la autenticación WebAuthn/FIDO2.
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
            throw new ServletException("Error inicializando servicios en FIDO2", e);
        }
    }

    /**
     * Procesa la solicitud de aserción FIDO2 enviada por el navegador.
     */
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");

        HttpSession session = req.getSession(true);
        Map<String, Object> jsonResponse = new HashMap<>();

        try {
            // 1. RECEPCIÓN DE DATOS Y CONTEXTO DE SESIÓN
            JsonObject json = gson.fromJson(req.getReader(), JsonObject.class);
            
            String modoLogin = json.has("modoLogin") ? json.get("modoLogin").getAsString() : "1FA";
            String dni = json.has("dni") ? json.get("dni").getAsString() : (String) session.getAttribute("webauthn_dni");
            String expectedChallenge = (String) session.getAttribute("webauthn_challenge");

            if (dni == null || dni.isEmpty()) {
                enviarError(resp, 400, "Identificación de usuario no encontrada.");
                return;
            }

            // 2. EXTRACCIÓN Y DECODIFICACIÓN DE COMPONENTES CRIPTOGRÁFICOS
            JsonObject responseJson = json.getAsJsonObject("response");
            byte[] credentialId = decodificarBase64(json.get("rawId").getAsString());
            byte[] clientDataJSON = decodificarBase64(responseJson.get("clientDataJSON").getAsString());
            byte[] authenticatorData = decodificarBase64(responseJson.get("authenticatorData").getAsString());
            byte[] signature = decodificarBase64(responseJson.get("signature").getAsString());

            // 3. VALIDACIÓN DEL DESAFÍO (CHALLENGE)
            // Previene ataques de repetición asegurando que la respuesta corresponde al desafío actual.
            JsonObject clientDataObj = gson.fromJson(new String(clientDataJSON, "UTF-8"), JsonObject.class);
            String receivedChallenge = clientDataObj.get("challenge").getAsString();
            if (expectedChallenge == null || !receivedChallenge.equals(expectedChallenge)) {
                enviarError(resp, 401, "El desafío de seguridad ha caducado o es inválido.");
                return;
            }

            // 4. VERIFICACIÓN DE LA CREDENCIAL EN EL REPOSITORIO
            UsuarioDAO.WebAuthnCredential cred = usuarioDAO.obtenerFido2(dni, credentialId);
            if (cred == null) {
                enviarError(resp, 404, "Llave FIDO2 no vinculada a este usuario.");
                return;
            }

            // 5. VALIDACIÓN DE FIRMA DIGITAL (Standard WebAuthn)
            boolean firmaOK = FirmaWeb.validarFirma(authenticatorData, clientDataJSON, signature, cred.getPublicKey());
            if (!firmaOK) {
                enviarError(resp, 401, "Firma FIDO2 inválida.");
                return;
            }

            // 6. GESTIÓN DEL MODELO DE CONFIANZA (Categoría 'TENER')
         
            @SuppressWarnings("unchecked")
            List<String> categoriasSuperadas = (List<String>) session.getAttribute("categoriasSuperadas");
            
            if (categoriasSuperadas == null) categoriasSuperadas = new ArrayList<>();
            if (!categoriasSuperadas.contains("TENER")) {
                categoriasSuperadas.add("TENER");
            }
            session.setAttribute("categoriasSuperadas", categoriasSuperadas);
            session.setAttribute("usuarioTemp", dni);

            // 7. ACTUALIZACIÓN DEL CONTADOR DE FIRMAS (Anticlonación)
            try {
                int signCount = ByteBuffer.wrap(authenticatorData).getInt(33);
                usuarioDAO.actualizarSignCountFido2(dni, credentialId, signCount);
            } catch (Exception e) {
                // Registro silencioso de fallo en contador
            }

            // 8. LÓGICA DE NAVEGACIÓN BASADA EN FACTORES ACUMULADOS
            if ("1FA".equals(modoLogin)) {
            	usuarioDAO.resetearIntentos(dni);
                // Login mediante llave física como único factor (Passwordless FIDO2)
                session.setAttribute("usuario", dni); 
                jsonResponse.put("success", true);
                jsonResponse.put("redirect", "bienvenido.jsp");
            } 
            else {
                // Verificación de si se cumple el criterio Multi-Factor (MFA)
                if (categoriasSuperadas.size() >= 2) {
                	usuarioDAO.resetearIntentos(dni);
                    session.setAttribute("usuario", dni);
                    jsonResponse.put("success", true);
                    jsonResponse.put("redirect", "bienvenido.jsp");
                } else {
                    // Refuerzo de identidad mediante OTP si solo existe este factor
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
            enviarError(resp, 500, "Error crítico en el proceso de autenticación FIDO2.");
        }
    }

    /**
     * Decodifica cadenas Base64 URL Safe para procesar los datos binarios de WebAuthn.
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
     * Envía una respuesta de error estructurada en formato JSON.
     */
    private void enviarError(HttpServletResponse resp, int code, String msg) throws IOException {
        resp.setStatus(code);
        Map<String, Object> error = new HashMap<>();
        error.put("success", false);
        error.put("message", msg);
        resp.getWriter().write(gson.toJson(error));
    }
}