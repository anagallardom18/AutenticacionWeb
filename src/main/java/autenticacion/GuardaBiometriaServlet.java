package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;
import java.io.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import com.google.gson.Gson;
import com.upokecenter.cbor.CBORObject;

/**
 * Servlet que gestiona el guardado de nuevas credenciales biométricas.
 * Recibe el paquete de 'attestation' del navegador, extrae la clave pública
 * y la vincula de forma permanente al DNI del usuario en la base de datos.
 */
@WebServlet("/GuardaBiometriaServlet")
public class GuardaBiometriaServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private UsuarioDAO usuarioDAO;
    private final Gson gson = new Gson();

    @Override
    public void init() throws ServletException {
        try {
            // Inicialización del DAO mediante el Pool de Conexiones
            Context ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            usuarioDAO = new UsuarioDAO(ds);
        } catch (Exception e) {
            throw new ServletException("Error inicializando UsuarioDAO en GuardaBiometria", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        
        // 1. VERIFICACIÓN DE SEGURIDAD: 
        // Solo un usuario que ya se ha iniciado sesión puede registrar su biometría.
        HttpSession session = req.getSession(false);
        if (session == null || session.getAttribute("usuario") == null) {
            enviarRespuesta(resp, 401, false, "Sesión no válida o expirada.");
            return;
        }
        
        String dniSesion = (String) session.getAttribute("usuario");

        try {
            // 2. PARSEO DEL JSON: Mapeo de la respuesta del navegador (WebAuthn API)
            CredencialData credential = gson.fromJson(req.getReader(), CredencialData.class);

            // Validar que el DNI del formulario coincida con el de la sesión activa para evitar suplantaciones
            if (credential == null || credential.dni == null || !credential.dni.equals(dniSesion)) {
                enviarRespuesta(resp, 403, false, "El DNI no coincide con la sesión activa.");
                return;
            }

            // 3. DECODIFICACIÓN BASE64URL: 
            // WebAuthn utiliza Base64 sin relleno (URL-Safe) para transmitir datos binarios.
            byte[] rawIdBytes = Base64.getUrlDecoder().decode(credential.rawId);
            byte[] attestationBytes = Base64.getUrlDecoder().decode(credential.response.attestationObject);
            
            // 4. EXTRACCIÓN DE LA CLAVE PÚBLICA:
            // El 'attestationObject' es un mapa CBOR que contiene el 'authData'.
            // Dentro de 'authData' está la clave pública en formato COSE.
            byte[] publicKeyBytes = extractPublicKey(attestationBytes);

            // 5. PERSISTENCIA:
            // Guardamos el ID de la credencial y la Clave Pública en la base de datos.
            Usuario usuario = new Usuario();
            usuario.setDni(dniSesion);

            boolean exito = usuarioDAO.guardarCredencialWebAuthn(usuario, rawIdBytes, publicKeyBytes);

            if (exito) {
                enviarRespuesta(resp, 200, true, "Biometría registrada correctamente.");
            } else {
                enviarRespuesta(resp, 500, false, "Error al guardar la credencial en la base de datos.");
            }

        } catch (IllegalArgumentException e) {
            enviarRespuesta(resp, 400, false, "Datos de autenticador inválidos: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            enviarRespuesta(resp, 500, false, "Error interno en el servidor: " + e.getMessage());
        }
    }

    /**
     * Extrae la Public Key.
     * Estructura de AuthData (estándar FIDO2):
     * - RPIDHash (32 bytes)
     * - Flags (1 byte)
     * - SignCounter (4 bytes)
     * - AttestedCredentialData (Variable):
     * - AAGUID (16 bytes)
     * - L (2 bytes, longitud del CredID)
     * - CredentialID (L bytes)
     * - CredentialPublicKey (Resto de bytes en formato CBOR/COSE)
     */
    private byte[] extractPublicKey(byte[] attestationObjectBytes) {
        // Decodificamos el objeto CBOR principal
        CBORObject attestationObj = CBORObject.DecodeFromBytes(attestationObjectBytes);
        byte[] authData = attestationObj.get(CBORObject.FromObject("authData")).GetByteString();

        // Verificamos el Bit 6 de los Flags (indica si hay datos de credencial presentes)
        int flags = authData[32] & 0xFF;
        if ((flags & 0x40) == 0) {
            throw new IllegalArgumentException("El paquete no contiene datos de credencial (Flag AT no presente).");
        }

        // Calculamos la longitud del Credential ID (Big Endian, bytes 53 y 54)
        int credentialIdLength = ((authData[53] & 0xFF) << 8) | (authData[54] & 0xFF);
        
        // Calculamos dónde empieza la clave pública:
        // 37 (RPIDHash + Flags + Counter) + 16 (AAGUID) + 2 (Length L) + ID de la llave
        int publicKeyOffset = 37 + 16 + 2 + credentialIdLength;

        // Extraemos el resto del array, que contiene la clave pública codificada en COSE
        return Arrays.copyOfRange(authData, publicKeyOffset, authData.length);
    }

    //Envía una respuesta JSON estandarizada al cliente.
    private void enviarRespuesta(HttpServletResponse resp, int status, boolean success, String msg) throws IOException {
        resp.setStatus(status);
        Map<String, Object> map = new HashMap<>();
        map.put("success", success);
        map.put("message", msg);
        resp.getWriter().write(gson.toJson(map));
    }

    // Clases POJO internas para facilitar la lectura del JSON con GSON
    static class CredencialData {
        String rawId;      // Identificador único generado por el dispositivo
        String dni;        // DNI del usuario que registra
        ResponseData response;
    }

    static class ResponseData {
        String attestationObject; // Datos binarios firmados por el hardware
    }
}