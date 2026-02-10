package autenticacion;

public class Usuario {
    private int id;
    private String dni;
    private String contrasena;
    private String correo;
    private String ipRegistro;
    private String ubicacion;
    private String ipPermitida;
    private Double latPermitida;
    private Double lonPermitida;
    private String totpSecret;

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
}
