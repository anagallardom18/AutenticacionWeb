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
 * Servlet encargado de la verificación de credenciales biométricas (WebAuthn).
 * Maneja la recepción de aserciones criptográficas desde el navegador y 
 * valida la firma digital contra la clave pública almacenada.
 */
@WebServlet("/AutBiometriaServlet")
public class AutBiometriaServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private final Gson gson = new Gson();
    private UsuarioDAO usuarioDAO;
    private ConfigService configService;
    private Correo servicioCorreo;

    /**
     * Inicialización de recursos y servicios mediante JNDI.
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
            throw new ServletException("Error inicializando servicios en AutBiometriaServlet", e);
        }
    }

    /**
     * Procesa la aserción biométrica enviada por el cliente.
     */
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");

        // Obtenemos la sesión actual o creamos una nueva si es login directo (1FA)
        HttpSession session = req.getSession(true); 
        Map<String, Object> jsonResponse = new HashMap<>();

        try {
            // 1. RECEPCIÓN Y PARSEO DE LA CARGA ÚTIL JSON
            JsonObject json = gson.fromJson(req.getReader(), JsonObject.class);
            
            // Resolución del DNI: Prioriza el enviado en el JSON para login directo
            String dni = (json.has("dni") && !json.get("dni").getAsString().isEmpty()) 
                         ? json.get("dni").getAsString() 
                         : (String) session.getAttribute("webauthn_dni");
            
            if (dni == null) dni = (String) session.getAttribute("usuarioTemp");

            String modoLogin = json.has("modoLogin") ? json.get("modoLogin").getAsString() : "1FA";

            if (dni == null || dni.isEmpty()) {
                enviarError(resp, 401, "Identificación de usuario no encontrada.");
                return;
            }

            // 2. EXTRACCIÓN DE COMPONENTES DE LA CREDENCIAL (WebAuthn Assertion)
            JsonObject responseJson = json.getAsJsonObject("response");
            byte[] credentialId = decodificarBase64(json.get("rawId").getAsString());
            byte[] clientDataJSON = decodificarBase64(responseJson.get("clientDataJSON").getAsString());
            byte[] authenticatorData = decodificarBase64(responseJson.get("authenticatorData").getAsString());
            byte[] signature = decodificarBase64(responseJson.get("signature").getAsString());

            // 3. RECUPERACIÓN DE LA CLAVE PÚBLICA DESDE LA BASE DE DATOS
            UsuarioDAO.WebAuthnCredential cred = usuarioDAO.obtenerBiometria(dni, credentialId);
            if (cred == null) {
                enviarError(resp, 404, "Credencial biométrica no registrada.");
                return;
            }

            // 4. VALIDACIÓN CRIPTOGRÁFICA DE LA FIRMA
            // Se verifica que la clave privada del dispositivo generó la firma sobre los datos del cliente
            boolean firmaOK = FirmaWeb.validarFirma(authenticatorData, clientDataJSON, signature, cred.getPublicKey());
            if (!firmaOK) {
                enviarError(resp, 401, "Firma biométrica inválida.");
                return;
            }

            // 5. PROTECCIÓN CONTRA ATAQUES DE REPLAY (Sign Count)
            // El contador debe incrementarse en cada uso para asegurar que la llave no ha sido clonada
            try {
                int signCount = ByteBuffer.wrap(authenticatorData).getInt(33);
                usuarioDAO.actualizarSignCountBiometria(dni, credentialId, signCount);
            } catch (Exception e) {
                System.err.println("Aviso: No se pudo actualizar signCount.");
            }

            // 6. GESTIÓN DE LA "MOCHILA" DE SEGURIDAD (Categoría 'SER')
           
            @SuppressWarnings("unchecked")
            List<String> categoriasSuperadas = (List<String>) session.getAttribute("categoriasSuperadas");
            
            if (categoriasSuperadas == null) categoriasSuperadas = new ArrayList<>();
            if (!categoriasSuperadas.contains("SER")) {
                categoriasSuperadas.add("SER");
            }
            session.setAttribute("categoriasSuperadas", categoriasSuperadas);
            session.setAttribute("usuarioTemp", dni);

            // 7. ORQUESTACIÓN DE NAVEGACIÓN POST-AUTENTICACIÓN
            if ("1FA".equals(modoLogin)) {
            	usuarioDAO.resetearIntentos(dni);
                // Caso A: El usuario ha entrado directamente con biometría (Passwordless)
                session.setAttribute("usuario", dni); 
                session.removeAttribute("categoriasSuperadas"); // Limpieza de sesión
                jsonResponse.put("success", true);
                jsonResponse.put("redirect", "bienvenido.jsp");
            } 
            else {
                // Caso B: Segundo factor o flujo de categorías superadas
                if (categoriasSuperadas.size() >= 2) {
                	usuarioDAO.resetearIntentos(dni);
                    session.setAttribute("usuario", dni);
                    session.removeAttribute("categoriasSuperadas");
                    jsonResponse.put("success", true);
                    jsonResponse.put("redirect", "bienvenido.jsp");
                } else {
                    // Si falta un factor, intentamos reforzar con OTP vía correo
                    Usuario usuario = usuarioDAO.obtenerUsuarioPorDNI(dni);
                    String correo = (usuario != null) ? usuario.getCorreo() : null;

                    if (correo != null && !correo.isEmpty()) {
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
                    } else {
                        jsonResponse.put("success", true);
                        jsonResponse.put("redirect", "loginAlternativo.jsp");
                    }
                }
            }

            resp.getWriter().write(gson.toJson(jsonResponse));

        } catch (Exception e) {
            e.printStackTrace();
            enviarError(resp, 500, "Error interno: " + e.getMessage());
        }
    }

    /**
     * Decodifica cadenas Base64, manejando tanto el estándar como el formato URL Safe.
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
     * Genera una respuesta de error estructurada en formato JSON.
     */
    private void enviarError(HttpServletResponse resp, int code, String msg) throws IOException {
        resp.setStatus(code);
        Map<String, Object> error = new HashMap<>();
        error.put("success", false);
        error.put("message", msg);
        resp.getWriter().write(gson.toJson(error));
    }
}