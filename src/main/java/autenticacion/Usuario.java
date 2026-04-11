package autenticacion;

import java.io.Serializable;

/**
 * Entidad que representa a un usuario en el sistema de autenticación adaptativa.
 * Implementa Serializable para permitir su almacenamiento en HttpSession si fuera necesario.
 */
public class Usuario implements Serializable {
    
    private static final long serialVersionUID = 1L;

    private int id;
    private String dni;
    private String contrasena;
    private String correo;
    
    // Atributos de Seguridad Adaptativa (Contexto)
    private String ipRegistro;   
    private String ubicacion;    
    private String ipPermitida;  
    private Double latPermitida; 
    private Double lonPermitida; 
    
    // Atributos de Segundo Factor (2FA)
    private String totpSecret;   

   
    private int intentos;        // Contador de fallos de login
    private String estado;       // 'ACTIVO' o 'BLOQUEADO'

    public Usuario() {}

    // --- MÉTODOS DE UTILIDAD LÓGICA ---

    /**
     * Indica si el usuario tiene activo el segundo factor por software (TOTP).
     */
    public boolean isTotpEnabled() {
        return totpSecret != null && !totpSecret.trim().isEmpty();
    }

    /**
     * Indica si el usuario tiene configurada una ubicación geográfica de confianza.
     */
    public boolean hasGeofencing() {
        return latPermitida != null && lonPermitida != null;
    }

    /**
     * Verifica si la cuenta está bloqueada.
     */
    public boolean isBloqueado() {
        return "BLOQUEADO".equalsIgnoreCase(this.estado);
    }

    // --- GETTERS Y SETTERS ---

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    public String getDni() { return dni; }
    public void setDni(String dni) { this.dni = dni; }

    public String getContrasena() { return contrasena; }
    public void setContrasena(String contrasena) { this.contrasena = contrasena; }

    public String getCorreo() { return correo; }
    public void setCorreo(String correo) { this.correo = correo; }

    public String getIpRegistro() { return ipRegistro; }
    public void setIpRegistro(String ipRegistro) { this.ipRegistro = ipRegistro; }

    public String getUbicacion() { return ubicacion; }
    public void setUbicacion(String ubicacion) { this.ubicacion = ubicacion; }

    public String getIpPermitida() { return ipPermitida; }
    public void setIpPermitida(String ipPermitida) { this.ipPermitida = ipPermitida; }

    public Double getLatPermitida() { return latPermitida; }
    public void setLatPermitida(Double latPermitida) { this.latPermitida = latPermitida; }

    public Double getLonPermitida() { return lonPermitida; }
    public void setLonPermitida(Double lonPermitida) { this.lonPermitida = lonPermitida; }

    public String getTotpSecret() { return totpSecret; }
    public void setTotpSecret(String totpSecret) { this.totpSecret = totpSecret; }

    // --- GETTERS Y SETTERS NUEVOS ---

    public int getIntentos() { return intentos; }
    public void setIntentos(int intentos) { this.intentos = intentos; }

    public String getEstado() { return estado; }
    public void setEstado(String estado) { this.estado = estado; }


    public String getLatitudHabitual() {
        return latPermitida != null ? String.valueOf(latPermitida) : null;
    }

    public String getLongitudHabitual() {
        return lonPermitida != null ? String.valueOf(lonPermitida) : null;
    }
   
    @Override
    public String toString() {
        return "Usuario{" + "id=" + id + ", dni='" + dni + '\'' + ", estado='" + estado + '\'' + '}';
    }
}