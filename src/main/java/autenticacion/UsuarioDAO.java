package autenticacion;

import javax.sql.DataSource;
import java.sql.*;
import java.util.*;
import java.util.Base64;

/**
 * Clase de Acceso a Datos (DAO) para la gestión de usuarios y credenciales de seguridad.
 * Esta clase centraliza todas las interacciones con la base de datos, implementando
 * la persistencia para el sistema de autenticación multi-factor (MFA) y seguridad adaptativa.
 */
public class UsuarioDAO {

    private final DataSource dataSource;


    /**
     * Constructor de la clase.
     * @param dataSource Pool de conexiones configurado en el servidor de aplicaciones.
     */
    public UsuarioDAO(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    // =========================================================================
    // 1. GESTIÓN DE USUARIOS Y SESIÓN 
    // =========================================================================

    /**
     * Recupera la información completa de un usuario a partir de su DNI.
     * Se utiliza en el inicio de sesión y para validar parámetros de seguridad adaptativa.
     * * @param dni del usuario.
     * @return Objeto Usuario con sus preferencias de seguridad, o null si no existe.
     */
    public Usuario obtenerUsuarioPorDNI(String dni) {
     
        String sql = "SELECT dni, correo, contrasena, totp_secret, ip_permitida, lat_permitida, lon_permitida, intentos, estado, fecha_bloqueo FROM usuarios WHERE dni=?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    Usuario usuario = new Usuario();
                    usuario.setDni(rs.getString("dni"));
                    usuario.setCorreo(rs.getString("correo"));
                    usuario.setContrasena(rs.getString("contrasena"));
                    usuario.setTotpSecret(rs.getString("totp_secret"));
                    usuario.setIpPermitida(rs.getString("ip_permitida"));
                    usuario.setLatPermitida((Double) rs.getObject("lat_permitida"));
                    usuario.setLonPermitida((Double) rs.getObject("lon_permitida"));
                    usuario.setIntentos(rs.getInt("intentos"));
                    usuario.setEstado(rs.getString("estado"));
                    return usuario;
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Valida el proceso de inicio de sesión gestionando la lógica de bloqueos.
     * Verifica la existencia del usuario, el estado de su cuenta y la validez 
     * de las credenciales, gestionando el contador de intentos fallidos.
     * * @param dni del usuario.
     * @param password Contraseña proporcionada en el formulario de login.
     * @return Estado del login: "OK", "NO_EXISTE", "BLOQUEADO" o "FALLO:n" (donde n son los intentos).
     */
    public String validarLoginCompleto(String dni, String password) {
        Usuario user = obtenerUsuarioPorDNI(dni);
        if (user == null) return "NO_EXISTE";

        // Comprobar bloqueo temporal (5 minutos)
        if ("BLOQUEADO".equals(user.getEstado())) {
            if (puedeDesbloquearse(dni)) {
                resetearIntentos(dni);
                user = obtenerUsuarioPorDNI(dni);
            } else {
                return "BLOQUEADO";
            }
        }

   
        if (user.getContrasena() != null && user.getContrasena().equals(password)) {
            resetearIntentos(dni);
            return "OK";
        } else {
            // Incremento de intentos fallidos si la clave no coincide
            int actuales = incrementarIntentos(dni);
            if (actuales >= 3) {
                bloquearUsuario(dni);
                return "BLOQUEADO";
            }
            return "FALLO:" + actuales;
        }
    }

    /**
     * Incrementa el contador de intentos fallidos en la base de datos.
     * Utiliza la función COALESCE para asegurar la integridad de la suma si el valor inicial es nulo.
     * * @param dni del usuario.
     * @return El número actualizado de intentos tras el incremento.
     */
    private int incrementarIntentos(String dni) {
        String sqlUpdate = "UPDATE usuarios SET intentos = COALESCE(intentos, 0) + 1 WHERE dni = ?";
        String sqlSelect = "SELECT intentos FROM usuarios WHERE dni = ?";
        int nuevosIntentos = 0;
        
        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(true);
            try (PreparedStatement psUpd = conn.prepareStatement(sqlUpdate)) {
                psUpd.setString(1, dni);
                psUpd.executeUpdate();
            }
            try (PreparedStatement psSel = conn.prepareStatement(sqlSelect)) {
                psSel.setString(1, dni);
                try (ResultSet rs = psSel.executeQuery()) {
                    if (rs.next()) {
                        nuevosIntentos = rs.getInt("intentos");
                    }
                }
            }
        } catch (SQLException e) { 
            e.printStackTrace(); 
        }
        return nuevosIntentos;
    }

    /**
     * Establece el estado del usuario como 'BLOQUEADO' y registra la marca temporal exacta.
     * Este método se activa automáticamente tras superar el umbral de intentos fallidos permitido.
     * * @param dni del usuario a bloquear.
     */
    private void bloquearUsuario(String dni) {
        String sql = "UPDATE usuarios SET estado = 'BLOQUEADO', fecha_bloqueo = NOW() WHERE dni = ?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            ps.executeUpdate();
        } catch (SQLException e) { e.printStackTrace(); }
    }

    /**
     * Verifica si ha transcurrido el tiempo de penalización necesario para permitir un nuevo acceso.
     * Actualmente el periodo de bloqueo está configurado en 5 minutos.
     * * @param dni del usuario bloqueado.
     * @return true si el usuario puede intentar loguearse de nuevo o no tiene bloqueo; false en caso contrario.
     */
    private boolean puedeDesbloquearse(String dni) {
        String sql = "SELECT fecha_bloqueo FROM usuarios WHERE dni = ?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    Timestamp fecha = rs.getTimestamp("fecha_bloqueo");
                    if (fecha == null) return true;
                    return (System.currentTimeMillis() - fecha.getTime()) > (5 * 60 * 1000);
                }
            }
        } catch (SQLException e) { e.printStackTrace(); }
        return false;
    }

    /**
     * Restablece los parámetros de seguridad del usuario a su estado inicial activo.
     * Limpia el contador de intentos y elimina la marca de tiempo de bloqueo.
     * * @param dni a resetear.
     */
    public void resetearIntentos(String dni) {
        String sql = "UPDATE usuarios SET intentos = 0, estado = 'ACTIVO', fecha_bloqueo = NULL WHERE dni = ?";
        
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            
            ps.setString(1, dni);
            ps.executeUpdate();        
        } catch (SQLException e) {
            System.err.println("Error al resetear intentos: " + e.getMessage());
        }
    }
    /**
     * Actualiza la contraseña 
     * * @param dni DNI del usuario a actualizar.
     * @param nuevaContrasena Nueva cadena de caracteres de la contraseña.
     * @return true si la actualización fue exitosa, false en caso contrario.
     */
    public boolean actualizarContrasena(String dni, String nuevaContrasena) {
        String sql = "UPDATE usuarios SET contrasena=? WHERE dni=?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
      
            ps.setString(1, nuevaContrasena);
            ps.setString(2, dni);
            
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    // =========================================================================
    // 2. MÉTODOS PARA WEBAUTHN / BIOMETRÍA Y LLAVES FÍSICAS 
    // =========================================================================

    /**
     * Obtiene una credencial de biometría específica.
     * @param dni DNI del propietario.
     * @param credentialId ID único de la credencial generado por el autenticador.
     * @return DTO con la clave pública y contador de uso.
     */
    public WebAuthnCredential obtenerBiometria(String dni, byte[] credentialId) {
        String sql = "SELECT public_key, sign_count FROM webauthn_credentials WHERE usuario_dni=? AND credential_id=?";
        return ejecutarConsultaCredencial(sql, dni, credentialId);
    }

    
    /**
     * Actualiza el contador de firmas (sign_count) para biometría.
     * El incremento del contador es vital para detectar clones de llaves de seguridad.
     */
    public void actualizarSignCountBiometria(String dni, byte[] credentialId, long newCount) {
        String sql = "UPDATE webauthn_credentials SET sign_count=? WHERE usuario_dni=? AND credential_id=?";
        ejecutarUpdateSignCount(sql, newCount, dni, credentialId);
    }

    /**
     * Registra una nueva credencial biométrica tras una ceremonia de registro WebAuthn exitosa.
     */
    public boolean guardarCredencialWebAuthn(Usuario usuario, byte[] credentialId, byte[] publicKey) {
        String sql = "INSERT INTO webauthn_credentials (usuario_dni, credential_id, public_key, sign_count) VALUES (?, ?, ?, 0)";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, usuario.getDni());
            ps.setBytes(2, credentialId);
            ps.setBytes(3, publicKey);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Actualiza el contador de firmas de la llave física FIDO2.
     * @param dni DNI del usuario.
     * @param credentialId ID de la credencial.
     * @param newCount Nuevo valor del contador (recibido como int o long).
     */
    public void actualizarSignCountFido2(String dni, byte[] credentialId, long newCount) {
        String sql = "UPDATE credenciales_fido2 SET sign_count=? WHERE dni=? AND credential_id=?";
        ejecutarUpdateSignCount(sql, newCount, dni, credentialId);
    }

    /**
     * Recupera una credencial de tipo FIDO2 (llave física de seguridad).
     */
    public WebAuthnCredential obtenerFido2(String dni, byte[] credentialId) {
        String sql = "SELECT public_key, sign_count FROM credenciales_fido2 WHERE dni=? AND credential_id=?";
        return ejecutarConsultaCredencial(sql, dni, credentialId);
    }

    /**
     * Registra una nueva llave física FIDO2 vinculada al usuario.
     */
    public boolean guardarCredencialFido2(String dni, byte[] credentialId, byte[] publicKey) {
        String sql = "INSERT INTO credenciales_fido2 (dni, credential_id, public_key, sign_count) VALUES (?, ?, ?, 0)";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            ps.setBytes(2, credentialId);
            ps.setBytes(3, publicKey);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Obtiene una Passkey (credencial residente) del usuario.
     */
    public WebAuthnCredential obtenerPasskey(String dni, byte[] credentialId) {
        String sql = "SELECT public_key, sign_count, user_handle FROM passkeys WHERE dni=? AND credential_id=?";
        return ejecutarConsultaCredencial(sql, dni, credentialId);
    }

    /**
     * Actualiza el contador de firmas (sign_count) específicamente para Passkeys.
     * Este contador es una medida de seguridad del estándar WebAuthn para detectar 
     * si una credencial ha sido clonada.
     * * @param dni DNI del usuario titular.
     * @param credentialId Identificador binario de la credencial.
     * @param newCount Nuevo valor del contador tras la última autenticación.
     */
    public void actualizarSignCountPasskey(String dni, byte[] credentialId, long newCount) {
        String sql = "UPDATE passkeys SET sign_count=? WHERE dni=? AND credential_id=?";
        ejecutarUpdateSignCount(sql, newCount, dni, credentialId);
    }

    /**
     * Registra una Passkey en la base de datos.
     */
    public boolean guardarCredencialPasskey(String dni, byte[] credentialId, byte[] publicKey, byte[] userHandle, int signCount) {
        String sql = "INSERT INTO passkeys (dni, credential_id, public_key, user_handle, sign_count) VALUES (?, ?, ?, ?, ?)";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            ps.setBytes(2, credentialId);
            ps.setBytes(3, publicKey);
            ps.setBytes(4, userHandle);
            ps.setInt(5, signCount);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    // =========================================================================
    // 3. MÉTODOS DE SOPORTE Y LISTADO
    // =========================================================================

    /**
     * Método auxiliar para listar credenciales en formato compatible con el navegador.
     * Codifica los IDs en Base64 URL Safe para su envío vía JSON.
     */
    private List<Map<String, Object>> listarGenerico(String sql, String dni) {
        List<Map<String, Object>> list = new ArrayList<>();
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    byte[] credId = rs.getBytes("credential_id");
                    String idB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(credId);
                    Map<String, Object> c = new HashMap<>();
                    c.put("type", "public-key");
                    c.put("id", idB64);
                    list.add(c);
                }
            }
        } catch (SQLException e) { throw new RuntimeException(e); }
        return list;
    }

    public List<Map<String, Object>> listarBiometria(String dni) {
        return listarGenerico("SELECT credential_id FROM webauthn_credentials WHERE usuario_dni=?", dni);
    }

    public List<Map<String, Object>> listarFido2(String dni) {
        return listarGenerico("SELECT credential_id FROM credenciales_fido2 WHERE dni=?", dni);
    }

    public List<Map<String, Object>> listarPasskey(String dni) {
        return listarGenerico("SELECT credential_id FROM passkeys WHERE dni=?", dni);
    }

    // =========================================================================
    // 4. MÉTODOS DE APOYO PRIVADOS (REUTILIZACIÓN DE CÓDIGO)
    // =========================================================================
    
    /**
     * Ejecuta consultas de lectura de credenciales de forma genérica.
     * Implementa lógica dinámica para manejar campos opcionales como 'user_handle'.
     */
    private WebAuthnCredential ejecutarConsultaCredencial(String sql, String dni, byte[] credentialId) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            ps.setBytes(2, credentialId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    WebAuthnCredential cred = new WebAuthnCredential();
                    cred.setPublicKey(rs.getBytes("public_key"));
                    cred.setSignCount(rs.getLong("sign_count"));
                    
                 // Verificación dinámica de columnas existentes en el ResultSet
                    try {
                        ResultSetMetaData rsmd = rs.getMetaData();
                        for (int i = 1; i <= rsmd.getColumnCount(); i++) {
                            if ("user_handle".equalsIgnoreCase(rsmd.getColumnName(i))) {
                                cred.setUserHandle(rs.getBytes("user_handle"));
                            }
                        }
                    } catch (SQLException e) { }
                    return cred;
                }
            }
        } catch (SQLException e) { e.printStackTrace(); }
        return null;
    }

    /**
     * Actualiza el contador de firmas en la tabla correspondiente.
     */
    private void ejecutarUpdateSignCount(String sql, long count, String dni, byte[] id) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, count);
            ps.setString(2, dni);
            ps.setBytes(3, id);
            ps.executeUpdate();
        } catch (SQLException e) { e.printStackTrace(); }
    }

    // =========================================================================
    // 5. SEGURIDAD ADAPTATIVA Y AUDITORÍA
    // =========================================================================

    /**
     * Actualiza el secreto TOTP (Google Authenticator)
     */
    public boolean actualizarTotpSecret(Usuario usuario) {
        String sql = "UPDATE usuarios SET totp_secret=? WHERE dni=?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, usuario.getTotpSecret());
            ps.setString(2, usuario.getDni());
            return ps.executeUpdate() > 0;
        } catch (SQLException e) { return false; }
    }

    /**
     * Registra un nuevo usuario.
     */
    public boolean registrarUsuario(Usuario usuario) {
        String sql = "INSERT INTO usuarios (dni, correo, contrasena, intentos, estado) VALUES (?, ?, ?, 0, 'ACTIVO')";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            
            ps.setString(1, usuario.getDni());
            ps.setString(2, usuario.getCorreo());
            ps.setString(3, usuario.getContrasena());
            
            return ps.executeUpdate() > 0;
        } catch (SQLException e) { 
            e.printStackTrace();
            return false; 
        }
    }

    
    /**
     * Establece la IP permitida para el acceso (Seguridad Adaptativa).
     */
    public void actualizarIpPermitida(String dni, String ipPermitida) {
        String sql = "UPDATE usuarios SET ip_permitida=? WHERE dni=?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, ipPermitida);
            ps.setString(2, dni);
            ps.executeUpdate();
        } catch (SQLException e) { throw new RuntimeException(e); }
    }

    /**
     * Establece las coordenadas geográficas de confianza del usuario (Geofencing).
     */
    public void actualizarUbicacionGPS(String dni, String lat, String lon) {
        String sql = "UPDATE usuarios SET lat_permitida=?, lon_permitida=? WHERE dni=?";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setDouble(1, Double.parseDouble(lat));
            ps.setDouble(2, Double.parseDouble(lon));
            ps.setString(3, dni);
            ps.executeUpdate();
        } catch (SQLException | NumberFormatException e) { throw new RuntimeException(e); }
    }

    /**
     * Registra un intento de acceso en el historial para auditoría de seguridad.
     */
    public void registrarAccesoIP(String dni, String ip, String pais, String ciudad) {
        String sql = "INSERT INTO device_locations (usuario_dni, ip, ip_country, ip_city) VALUES (?, ?, ?, ?)";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, dni);
            ps.setString(2, ip);
            ps.setString(3, pais);
            ps.setString(4, ciudad);
            ps.executeUpdate();
        } catch (SQLException e) { throw new RuntimeException(e); }
    }

    
    
    /**
     * Obtiene url de la base de datos
     */
    public String obtenerUrlPublica() {
        String sql = "SELECT valor FROM settings WHERE clave = 'URL_PUBLICA'";
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            
            if (rs.next()) {
                return rs.getString("valor");
            }
        } catch (SQLException e) {
        	 System.out.println("Error al leer URL_PUBLICA de la BD: " + e.getMessage());
        }
        return null;
    }
    
 // =========================================================================
    // CLASE INTERNA DTO
    // =========================================================================

    /**
     * Data Transfer Object que representa la información criptográfica de una 
     * credencial WebAuthn almacenada en el sistema.
     */
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
}