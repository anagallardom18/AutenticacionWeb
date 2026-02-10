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

import autenticacion.GuardaCredencialServlet.CredencialData;


@WebServlet("/GuardaFido2Servlet")
public class GuardaFido2Servlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {

        Gson gson = new Gson();
        CredencialData credential = null;

        try {
            credential = gson.fromJson(req.getReader(), CredencialData.class);
        } catch (Exception e) {
            e.printStackTrace();
            resp.sendError(400, "JSON inválido");
            return;
        }

        if (credential == null || credential.dni == null) {
            resp.sendError(400, "Falta el DNI o el cuerpo de la credencial está vacío.");
            return;
        }

        try {
            //decodificar la credencial
        	 byte[] rawIdBytes = decodeBase64Url(credential.rawId);
        	 byte[] publicKeyBytes = extractPublicKey(decodeBase64Url(credential.response.attestationObject));

             
            UsuarioDAO.guardarCredencialFido2(
                    credential.dni,
                    rawIdBytes,
                    publicKeyBytes
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
            throw new IllegalArgumentException("Attestation object missing valid authData.");
        }

        byte[] authData = authDataObj.GetByteString();

        final int AUTH_DATA_FIXED_LENGTH = 37;

        int flags = authData[32] & 0xFF;
        if ((flags & 0x40) == 0) {
            throw new IllegalArgumentException("Authenticator Data missing AT flag.");
        }

        int credentialIdLength = (authData[53] & 0xFF) << 8 | (authData[54] & 0xFF);
        int publicKeyOffset = AUTH_DATA_FIXED_LENGTH + 16 + 2 + credentialIdLength;

        return Arrays.copyOfRange(authData, publicKeyOffset, authData.length);
    }
    private byte[] decodeBase64Url(String b64url) {
        String base64 = b64url.replace('-', '+').replace('_', '/');
        while (base64.length() % 4 != 0) base64 += "=";
        return Base64.getDecoder().decode(base64);
    }
    static class CredencialData {
        String id;
        String rawId;
        String dni;
        ResponseData response;
    }

    static class ResponseData {
        String attestationObject;
        String clientDataJSON;
    }
}