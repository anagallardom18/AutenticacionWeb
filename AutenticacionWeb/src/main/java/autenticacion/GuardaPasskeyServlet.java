package autenticacion;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Base64;
import java.util.Arrays;

import com.google.gson.Gson;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

@WebServlet("/GuardaPasskeyServlet")
public class GuardaPasskeyServlet extends HttpServlet {

    private final Gson gson = new Gson();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {

        CredencialData credential;
        try {
            credential = gson.fromJson(req.getReader(), CredencialData.class);
        } catch (Exception e) {
            e.printStackTrace();
            resp.sendError(400, "JSON inválido");
            return;
        }

        if (credential == null || credential.response == null) {
            resp.sendError(400, "Cuerpo de credencial vacío");
            return;
        }

        try {
            //decodificar rawId y attestationObject
            byte[] rawIdBytes = decodeBase64Url(credential.rawId);
            byte[] attestationObjectBytes = decodeBase64Url(credential.response.attestationObject);

            //extraer la clave pública del attestationObject
            byte[] publicKeyBytes = extractPublicKey(attestationObjectBytes);

            //intentar extraer userHandle si existe
            byte[] userHandleBytes = null;
            if (credential.response.userHandle != null) {
                userHandleBytes = decodeBase64Url(credential.response.userHandle);
            }

            
            //guardar en la base de datos
            UsuarioDAO.guardarCredencialPasskey(
                    credential.dni,
                    rawIdBytes,
                    publicKeyBytes,
                    userHandleBytes,
                    0  // signCount inicial
            );

        } catch (Exception e) {
            e.printStackTrace();
            resp.sendError(500, "Error al guardar la credencial: " + e.getMessage());
            return;
        }

        resp.setContentType("application/json");
        resp.getWriter().write("{\"success\":true}");
    }

    private byte[] extractPublicKey(byte[] attestationObjectBytes) throws Exception {
        CBORObject attestationObj = CBORObject.DecodeFromBytes(attestationObjectBytes);
        CBORObject authDataObj = attestationObj.get(CBORObject.FromObject("authData"));

        if (authDataObj == null || authDataObj.getType() != CBORType.ByteString) {
            throw new IllegalArgumentException("Attestation object missing authData.");
        }

        byte[] authData = authDataObj.GetByteString();
        final int AUTH_DATA_FIXED_LENGTH = 37;

        //verificar la bandera de attestation (AT)
        int flags = authData[32] & 0xFF;
        if ((flags & 0x40) == 0) {
            throw new IllegalArgumentException("Authenticator Data missing AT flag.");
        }

        //calcular offset de credentialId y publicKey
        int credentialIdLength = (authData[53] & 0xFF) << 8 | (authData[54] & 0xFF);
        int publicKeyOffset = AUTH_DATA_FIXED_LENGTH + 16 + 2 + credentialIdLength;

        //extraer solo la clave pública (bytes CBOR)
        if (publicKeyOffset >= authData.length) {
            throw new IllegalArgumentException("Offset de publicKey fuera de rango.");
        }

        return Arrays.copyOfRange(authData, publicKeyOffset, authData.length);
    }

    private byte[] decodeBase64Url(String b64url) {
        String base64 = b64url.replace('-', '+').replace('_', '/');
        while (base64.length() % 4 != 0) base64 += "=";
        return Base64.getDecoder().decode(base64);
    }

    //clases internas para mapear JSON del navegador
    static class CredencialData {
        String id;
        String rawId;
        String dni;
        ResponseData response;
    }

    static class ResponseData {
        String attestationObject;
        String clientDataJSON;
        String userHandle; 
    }
}
