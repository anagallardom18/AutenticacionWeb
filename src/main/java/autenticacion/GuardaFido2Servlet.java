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

/**
 * Servlet encargado de registrar llaves de seguridad físicas (FIDO2).
 * Procesa el objeto de "attestation" generado por el hardware para extraer la clave pública.
 */
@WebServlet("/GuardaFido2Servlet")
public class GuardaFido2Servlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private UsuarioDAO usuarioDAO;
    private final Gson gson = new Gson();

    @Override
    public void init() throws ServletException {
        try {
            // Inicialización de la conexión a la base de datos vía JNDI
            Context ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            usuarioDAO = new UsuarioDAO(ds);
        } catch (Exception e) { 
            throw new ServletException("Error inicializando el DAO en GuardaFido2", e); 
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");

        // 1. VALIDACIÓN DE SESIÓN: Solo usuarios ya autenticados pueden registrar una nueva llave física en su perfil.
        HttpSession session = req.getSession(false);
        if (session == null || session.getAttribute("usuario") == null) {
            enviarRespuesta(resp, 401, false, "Sesión no válida.");
            return;
        }

        String dniSesion = (String) session.getAttribute("usuario");

        try {
            // 2. LECTURA DEL JSON: Se recibe la estructura CredentialData desde el frontend (JS)
            CredencialData credential = gson.fromJson(req.getReader(), CredencialData.class);
            
            // Verificación de integridad: El DNI del payload debe coincidir con el de la sesión
            if (credential == null || !dniSesion.equals(credential.dni)) {
                enviarRespuesta(resp, 403, false, "El DNI no coincide con la sesión activa.");
                return;
            }

            // 3. DECODIFICACIÓN: WebAuthn envía datos en Base64URL (sin padding)
            // rawId: El identificador único de la credencial dentro de la llave física
            byte[] rawId = Base64.getUrlDecoder().decode(credential.rawId);
            // attestationObject: Objeto binario codificado en CBOR que contiene la clave pública
            byte[] attestation = Base64.getUrlDecoder().decode(credential.response.attestationObject);
            
            // 4. EXTRACCIÓN CRIPTOGRÁFICA: Se navega por el binario para obtener la clave pública (COSE)
            byte[] publicKey = extractPublicKey(attestation);

            // 5. PERSISTENCIA: Se guarda la credencial en la tabla de FIDO2
            boolean exito = usuarioDAO.guardarCredencialFido2(dniSesion, rawId, publicKey);
            
            enviarRespuesta(resp, exito ? 200 : 500, exito, 
                           exito ? "Dispositivo FIDO2 registrado con éxito." : "Error al guardar en la base de datos.");
            
        } catch (Exception e) {
            e.printStackTrace();
            enviarRespuesta(resp, 500, false, "Error técnico en el registro: " + e.getMessage());
        }
    }

    /**
     * Procesa el objeto de attestation (CBOR) para extraer la clave pública.
     * Estructura interna de authData:
     * - RPIDHash (32 bytes)
     * - Flags (1 byte)
     * - Counter (4 bytes)
     * - AAGUID (16 bytes)
     * - L (2 bytes: longitud del CredentialID)
     * - CredentialID (L bytes)
     * - Public Key (Restante)
     */
    private byte[] extractPublicKey(byte[] attestationBytes) {
        // Decodificamos el mapa CBOR principal
        CBORObject attestationObj = CBORObject.DecodeFromBytes(attestationBytes);
        // Obtenemos los 'authData' (datos del autenticador)
        byte[] authData = attestationObj.get(CBORObject.FromObject("authData")).GetByteString();
        
        // Calculamos la longitud del Credential ID (está en los bytes 53 y 54)
        int credentialIdLength = ((authData[53] & 0xFF) << 8) | (authData[54] & 0xFF);
        
        // El offset de la clave pública se calcula sumando:
        // 37 (header inicial) + 16 (AAGUID) + 2 (campo longitud) + longitud del ID
        int publicKeyOffset = 37 + 16 + 2 + credentialIdLength;
        
        // Devolvemos el resto de los bytes, que corresponden a la clave pública en formato COSE
        return Arrays.copyOfRange(authData, publicKeyOffset, authData.length);
    }


    private void enviarRespuesta(HttpServletResponse resp, int status, boolean success, String msg) throws IOException {
        resp.setStatus(status);
        Map<String, Object> map = new HashMap<>();
        map.put("success", success);
        map.put("message", msg);
        resp.getWriter().write(gson.toJson(map));
    }

    // Clases POJO internas para el mapeo automático de GSON
    static class CredencialData { String rawId; String dni; ResponseData response; }
    static class ResponseData { String attestationObject; }
}