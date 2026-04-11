package autenticacion;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;

import java.io.IOException;
import java.util.Base64;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.Gson;
import com.upokecenter.cbor.CBORObject;

//Servlet para el registro de Passkeys
@WebServlet("/GuardaPasskeyServlet")
public class GuardaPasskeyServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private UsuarioDAO usuarioDAO;
    private final Gson gson = new Gson();

    @Override
    public void init() throws ServletException {
        try {
            // Inicialización de recursos JNDI para la persistencia
            Context ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            usuarioDAO = new UsuarioDAO(ds);
        } catch (Exception e) { 
            throw new ServletException("Error inicializando servicios en GuardaPasskey", e); 
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");

        // 1. VALIDACIÓN DE IDENTIDAD: Solo un usuario con sesión iniciada puede registrar una Passkey
        HttpSession session = req.getSession(false);
        if (session == null || session.getAttribute("usuario") == null) {
            enviarRespuesta(resp, 401, false, "Sesión no válida o expirada.");
            return;
        }

        String dniSesion = (String) session.getAttribute("usuario");

        try {
            // 2. RECEPCIÓN DEL PAYLOAD: Se obtiene el JSON generado por la API navigator.credentials.create()
            CredencialData credential = gson.fromJson(req.getReader(), CredencialData.class);
            
            // Comprobación del DNI enviado y el DNI en sesión
            if (credential == null || !dniSesion.equals(credential.dni)) {
                enviarRespuesta(resp, 403, false, "El DNI no coincide con el usuario en sesión.");
                return;
            }

            // 3. DECODIFICACIÓN DE DATOS WEBAUTHN:
            // rawId: El identificador único de la Passkey.
            // attestationObject: Binario CBOR con la clave pública y datos del autenticador.
            byte[] rawId = Base64.getUrlDecoder().decode(credential.rawId);
            byte[] attestation = Base64.getUrlDecoder().decode(credential.response.attestationObject);
            
            // 4. EXTRACCIÓN DE LA CLAVE PÚBLICA (COSE):
            byte[] publicKey = extractPublicKey(attestation);
            
            // 5. MANEJO DEL USER HANDLE: 
            // El 'userHandle' es un ID interno que el dispositivo guarda para reconocer al usuario
            // sin que este tenga que introducir su DNI en el próximo login.
            byte[] userHandle = (credential.response.userHandle != null) ? 
                                Base64.getUrlDecoder().decode(credential.response.userHandle) : null;

            // 6. PERSISTENCIA: Almacenamos la Passkey vinculada al usuario
            // Se inicializa el contador de firmas (signCount) en 0.
            boolean exito = usuarioDAO.guardarCredencialPasskey(dniSesion, rawId, publicKey, userHandle, 0);
            
            enviarRespuesta(resp, exito ? 200 : 500, exito, 
                           exito ? "Passkey registrada correctamente." : "Error al guardar en la base de datos.");

        } catch (Exception e) {
            e.printStackTrace();
            enviarRespuesta(resp, 500, false, "Error técnico en el registro de Passkey: " + e.getMessage());
        }
    }

    /**
     * Procesa el objeto de attestation (CBOR) para extraer la clave pública.
     * Estructura: AuthData = HashRP(32) + Flags(1) + Counter(4) + AAGUID(16) + L(2) + CredID(L) + PubKey
     */
    private byte[] extractPublicKey(byte[] attestationBytes) {
        // Decodificación del mapa CBOR (Concise Binary Object Representation)
        CBORObject attestationObj = CBORObject.DecodeFromBytes(attestationBytes);
        byte[] authData = attestationObj.get(CBORObject.FromObject("authData")).GetByteString();
        
        // La longitud del ID de la credencial se encuentra en los bytes 53 y 54 del authData
        int credentialIdLength = ((authData[53] & 0xFF) << 8) | (authData[54] & 0xFF);
        
        // El offset para llegar a la clave pública es la suma de las cabeceras fijas y el ID dinámico
        int publicKeyOffset = 37 + 16 + 2 + credentialIdLength;
        
        // Vuelve al segmento que contiene la clave pública en formato COSE
        return Arrays.copyOfRange(authData, publicKeyOffset, authData.length);
    }

  
    private void enviarRespuesta(HttpServletResponse resp, int status, boolean success, String msg) throws IOException {
        resp.setStatus(status);
        Map<String, Object> map = new HashMap<>();
        map.put("success", success);
        map.put("message", msg);
        resp.getWriter().write(gson.toJson(map));
    }

    // Clases POJO para la deserialización de GSON
    static class CredencialData { 
        String rawId; 
        String dni; 
        ResponseData response; 
    }
    
    static class ResponseData { 
        String attestationObject; 
        String userHandle; // Identificador de usuario para logins "username-less"
    }
}