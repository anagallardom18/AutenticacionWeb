package autenticacion;

import java.sql.*;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Base64;

public class UsuarioDAO {


    private static final String URL = "jdbc:mysql://localhost:3306/autenticacion_db";
    private static final String USER = "root";
    private static final String PASS = "root";
    

    //obtener usuario por dni
    public static Usuario obtenerUsuarioPorDNI(String dni) {
        Usuario usuario = null;
        String sql = "SELECT dni, correo, contrasena, totp_secret FROM usuarios WHERE dni=?";
        try (Connection conn = ConexionBD.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                usuario = new Usuario();
                usuario.setDni(rs.getString("dni"));
                usuario.setCorreo(rs.getString("correo"));
                usuario.setContrasena(rs.getString("contrasena"));
                usuario.setTotpSecret(rs.getString("totp_secret"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return usuario;
    }

 
    //verificar si existe un usuario por correo
    public static boolean usuarioExistePorCorreo(String correo) {
        boolean existe = false;
        try (Connection con = DriverManager.getConnection(URL, USER, PASS);
             PreparedStatement ps = con.prepareStatement("SELECT COUNT(*) FROM usuarios WHERE correo=?")) {
            ps.setString(1, correo);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                existe = rs.getInt(1) > 0;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return existe;
    }

    //registrar un nuevo usuario

    public static void registrarUsuario(Usuario usuario) {
        try (Connection con = DriverManager.getConnection(URL, USER, PASS);
             PreparedStatement ps = con.prepareStatement(
                     "INSERT INTO usuarios (dni, contrasena, correo, ip_registro, ubicacion, ip_permitida, lat_permitida, lon_permitida, totp_secret) " +
                             "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            ps.setString(1, usuario.getDni());
            ps.setString(2, usuario.getContrasena());
            ps.setString(3, usuario.getCorreo());
            ps.setString(4, usuario.getIpRegistro());
            ps.setString(5, usuario.getUbicacion());
            ps.setString(6, usuario.getIpPermitida());
            ps.setObject(7, usuario.getLatPermitida());
            ps.setObject(8, usuario.getLonPermitida());
            ps.setString(9, usuario.getTotpSecret());
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //actualizar contraseña por correo

    public static void actualizarContrasena(String correo, String nuevaContrasena) {
        try (Connection con = DriverManager.getConnection(URL, USER, PASS);
             PreparedStatement ps = con.prepareStatement(
                     "UPDATE usuarios SET contrasena=? WHERE correo=?")) {
            ps.setString(1, nuevaContrasena);
            ps.setString(2, correo);
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //actualizar IP permitida por DNI
    public static void actualizarIpPermitida(String dni, String ipPermitida) {
        try (Connection con = DriverManager.getConnection(URL, USER, PASS);
             PreparedStatement ps = con.prepareStatement(
                     "UPDATE usuarios SET ip_permitida=? WHERE dni=?")) {
            ps.setString(1, ipPermitida);
            ps.setString(2, dni);
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //actualizar ubicación permitida
    public static void actualizarUbicacionPermitida(String dni, double lat, double lon) {
        try (Connection con = DriverManager.getConnection(URL, USER, PASS);
             PreparedStatement ps = con.prepareStatement(
                     "UPDATE usuarios SET lat_permitida=?, lon_permitida=? WHERE dni=?")) {
            ps.setDouble(1, lat);
            ps.setDouble(2, lon);
            ps.setString(3, dni);
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //registrar acceso de IP
    public static void registrarAccesoIP(String dni, String ip, String pais, String ciudad) {
        String sql = "INSERT INTO device_locations (usuario_dni, ip, ip_country, ip_city) VALUES (?, ?, ?, ?)";
        try (Connection con = DriverManager.getConnection(URL, USER, PASS);
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, dni);
            ps.setString(2, ip);
            ps.setString(3, pais);
            ps.setString(4, ciudad);
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void actualizarTotpSecret(Usuario usuario) {
        String sql = "UPDATE usuarios SET totp_secret=? WHERE dni=?";
        try (Connection con = ConexionBD.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, usuario.getTotpSecret());
            ps.setString(2, usuario.getDni());
            ps.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void guardarCredencialWebAuthn(Usuario usuario, byte[] credentialId, byte[] publicKey) {
        String sql = "INSERT INTO webauthn_credentials (usuario_dni, credential_id, public_key, sign_count) VALUES (?, ?, ?, ?)";
        try (Connection con = ConexionBD.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, usuario.getDni());
            ps.setBytes(2, credentialId);
            ps.setBytes(3, publicKey);
            ps.setLong(4, 0);
            ps.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void guardarCredencial(String dni, byte[] credentialId, byte[] publicKey) throws SQLException {
        String sql = "INSERT INTO webauthn_credentials (usuario_dni, credential_id, public_key, sign_count) VALUES (?, ?, ?, ?)";
        try (Connection conn = ConexionBD.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            ps.setBytes(2, credentialId);
            ps.setBytes(3, publicKey);
            ps.setLong(4, 0);
            ps.executeUpdate();
        }
    }

    public static List<Map<String,Object>> obtenerCredenciales(String dni) throws SQLException {
        List<Map<String,Object>> allowCreds = new ArrayList<>();
        String sql = "SELECT credential_id FROM webauthn_credentials WHERE usuario_dni=?";
        try (Connection conn = ConexionBD.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                byte[] credId = rs.getBytes("credential_id");
                String idB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(credId);
                Map<String,Object> c = new HashMap<>();
                c.put("type", "public-key");
                c.put("id", idB64);
                allowCreds.add(c);
            }
        }
        return allowCreds;
    }

    //obtener public key y sign_count de una credencial
    public static WebAuthnCredential obtenerCredencial(String dni, byte[] credentialId) {
        WebAuthnCredential cred = null;
        try (Connection conn = ConexionBD.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT public_key, sign_count FROM webauthn_credentials WHERE usuario_dni=? AND credential_id=?")) {
            ps.setString(1, dni);
            ps.setBytes(2, credentialId);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                cred = new WebAuthnCredential();
                cred.setPublicKey(rs.getBytes("public_key"));
                cred.setSignCount(rs.getLong("sign_count"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return cred;
    }

    //actualizar sign_count de una credencial
    public static void actualizarSignCount(String dni, byte[] credentialId, long newCount) {
        try (Connection conn = ConexionBD.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "UPDATE webauthn_credentials SET sign_count=? WHERE usuario_dni=? AND credential_id=?")) {
            ps.setLong(1, newCount);
            ps.setString(2, dni);
            ps.setBytes(3, credentialId);
            ps.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    //devolver credenciales
    public static class WebAuthnCredential {
        private byte[] publicKey;
        private long signCount;
        private byte[] userHandle;

        public byte[] getPublicKey() { return publicKey; }
        public void setPublicKey(byte[] publicKey) { this.publicKey = publicKey; }
        public long getSignCount() { return signCount; }
        public void setSignCount(long signCount) { this.signCount = signCount; }
        public byte[] getUserHandle() { return userHandle; }
        public void setUserHandle(byte[] userHandle) { this.userHandle = userHandle; }
    }
    
    public static void guardarCredencialFido2(String dni, byte[] credentialId, byte[] publicKey) throws SQLException {
        String sql = "INSERT INTO credenciales_fido2 (dni, credential_id, public_key, sign_count) VALUES (?, ?, ?, ?)";
        try (Connection conn = ConexionBD.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            ps.setBytes(2, credentialId);
            ps.setBytes(3, publicKey);
            ps.setLong(4, 0);
            ps.executeUpdate();
        }
    }

    public static List<Map<String,Object>> obtenerCredencialesFido2(String dni) throws SQLException {
        List<Map<String,Object>> allowCreds = new ArrayList<>();
        String sql = "SELECT credential_id FROM credenciales_fido2 WHERE dni=?";
        try (Connection conn = ConexionBD.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                byte[] credId = rs.getBytes("credential_id");
                String idB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(credId);
                Map<String,Object> c = new HashMap<>();
                c.put("type", "public-key");
                c.put("id", idB64);
                allowCreds.add(c);
            }
        }
        return allowCreds;
    }

    public static WebAuthnCredential obtenerCredencialFido2(String dni, byte[] credentialId) throws SQLException {
        WebAuthnCredential cred = null;
        String sql = "SELECT public_key, sign_count FROM credenciales_fido2 WHERE dni=? AND credential_id=?";
        try (Connection conn = ConexionBD.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            ps.setBytes(2, credentialId);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                cred = new WebAuthnCredential();
                cred.setPublicKey(rs.getBytes("public_key"));
                cred.setSignCount(rs.getLong("sign_count"));
            }
        } 
        return cred;
    }

    public static void actualizarSignCountFido2(String dni, byte[] credentialId, long newCount) throws SQLException{
        String sql = "UPDATE credenciales_fido2 SET sign_count=? WHERE dni=? AND credential_id=?";
        try (Connection conn = ConexionBD.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, newCount);
            ps.setString(2, dni);
            ps.setBytes(3, credentialId);
            ps.executeUpdate();
        } 
    }
    public static List<Map<String, Object>> obtenerCredencialesPasskey(String dni) throws Exception {

        List<Map<String, Object>> list = new ArrayList<>();

        String sql = "SELECT credential_id FROM passkeys WHERE dni = ?";
        
        try (Connection con = ConexionBD.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {

            ps.setString(1, dni);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    byte[] credId = rs.getBytes("credential_id");

                    String credIdBase64Url = Base64.getUrlEncoder()
                            .withoutPadding()
                            .encodeToString(credId);

                    Map<String, Object> cred = new HashMap<>();
                    cred.put("type", "public-key");
                    cred.put("id", credIdBase64Url);

                    list.add(cred);
                }
            }
        }

        return list;
    }

    //guarda una nueva credencial Passkey
    public static void guardarCredencialPasskey(
            String dni,
            byte[] credentialId,
            byte[] publicKey,
            byte[] userHandle,
            int signCount
    ) throws SQLException {

        String sql = "INSERT INTO passkeys (dni, credential_id, public_key, user_handle, sign_count) VALUES (?, ?, ?, ?, ?)";

        try (Connection conn = ConexionBD.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, dni);
            ps.setBytes(2, credentialId);
            ps.setBytes(3, publicKey);

            if (userHandle != null) {
                ps.setBytes(4, userHandle);
            } else {
                ps.setNull(4, Types.BLOB);
            }

            ps.setInt(5, signCount);

            ps.executeUpdate();
        }
    }

    //obtiene una credencial específica de Passkey para login
    public static WebAuthnCredential obtenerCredencialPasskey(String dni, byte[] credentialId) throws SQLException {
        WebAuthnCredential cred = null;
        String sql = "SELECT public_key, user_handle, sign_count FROM passkeys WHERE dni=? AND credential_id=?";

        try (Connection conn = ConexionBD.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, dni);
            ps.setBytes(2, credentialId);

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    cred = new WebAuthnCredential();
                    cred.setPublicKey(rs.getBytes("public_key"));
                    cred.setSignCount(rs.getLong("sign_count"));
                    byte[] userHandle = rs.getBytes("user_handle");
                    if (userHandle != null) {
                        cred.setUserHandle(userHandle);
                    }
                }
            }
        }

        return cred;
    }

    //actualiza el contador de firmas de la credencial
    public static void actualizarSignCountPasskey(String dni, byte[] credentialId, long newCount) throws SQLException {
        String sql = "UPDATE passkeys SET sign_count=? WHERE dni=? AND credential_id=?";

        try (Connection conn = ConexionBD.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setLong(1, newCount);
            ps.setString(2, dni);
            ps.setBytes(3, credentialId);
            ps.executeUpdate();
        }
    }
}