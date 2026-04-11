package autenticacion;

import java.sql.Connection;
import java.sql.SQLException;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;
import jakarta.annotation.Resource;


 //Gestión de conexiones con la base de datos.
public class ConexionBD {

    
    @Resource(name = "jdbc/autenticacion")
    private static DataSource fuente;
    
    // Bloque estático: se ejecuta una sola vez cuando la clase se carga en memoria
    static {
        if (fuente == null) {
            InitialContext ctx;
            try {
                // JNDI (Java Naming and Directory Interface):
                // Busca el recurso por su nombre dentro del entorno del servidor.
                ctx = new InitialContext();
                fuente = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            } catch (NamingException e) {
                // Si falla, el error se registra pero se ignora para no detener el despliegue
                System.err.println("No se pudo localizar el DataSource jdbc/autenticacion");
            }
        }
    }

    /**
     * @return Connection objeto de conexión SQL
     * @throws SQLException si el servidor de base de datos no responde o el pool está lleno.
     */
    public static Connection getConnection() throws SQLException {
        if (fuente == null) {
            throw new SQLException("El DataSource no está inicializado correctamente.");
        }
        return fuente.getConnection();
    }
}
