package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;
import java.io.*;
import com.google.gson.Gson;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.util.Arrays;
import java.util.Base64;

@WebServlet("/GuardaCredencialServlet")
public class GuardaCredencialServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        Gson gson = new Gson();
        CredencialData credential;

        try {
            credential = gson.fromJson(req.getReader(), CredencialData.class);
        } catch (Exception e) {
            e.printStackTrace();
            resp.sendError(400, "JSON inválido");
            return;
        }

        if (credential.dni == null) {
            resp.sendError(400, "Falta el DNI");
            return;
        }

        try {
            //decodificar la credencial
            byte[] rawIdBytes = decodeBase64Url(credential.rawId);
            byte[] attestationBytes = decodeBase64Url(credential.response.attestationObject);
            byte[] publicKeyBytes = extractPublicKey(attestationBytes);

            UsuarioDAO.guardarCredencial(
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


    private byte[] decodeBase64Url(String b64url) {
        String base64 = b64url.replace('-', '+').replace('_', '/');
        while (base64.length() % 4 != 0) base64 += "=";
        return Base64.getDecoder().decode(base64);
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


    // JSON
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
