package autenticacion;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import javax.sql.DataSource;

/**
 * SERVICIO DE CONFIGURACIÓN DINÁMICA (ConfigService)
 * * Esta clase implementa un patrón de "Caché de Configuración". 
 * Su función es leer los parámetros técnicos de la tabla 'settings' al inicio 
 * de la aplicación y mantenerlos en memoria (HashMap) para optimizar el rendimiento, 
 * evitando consultas constantes a la base de datos cada vez que se necesita 
 * una propiedad (como las credenciales SMTP).
 */
public class ConfigService {
    
    // Diccionario en memoria para un acceso instantáneo a los parámetros
    private final Map<String, String> cacheSettings = new HashMap<>();

    /**
     * Constructor del servicio. Realiza la carga inicial desde la base de datos.
     * * @param ds DataSource configurado en el servidor para obtener la conexión física.
     */
    public ConfigService(DataSource ds) {
        // Consulta alineada estrictamente con el archivo schema.sql
        String sql = "SELECT clave, valor FROM settings";
        
        // Uso de try-with-resources para garantizar el cierre de recursos de red y base de datos
        try (Connection con = ds.getConnection();
             PreparedStatement ps = con.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            
            while (rs.next()) {
                // Almacenamos el par clave-valor en nuestro mapa interno
                cacheSettings.put(rs.getString("clave"), rs.getString("valor"));
            }
            
            // Log de auditoría interna para el arranque del servidor
            System.out.println("LOG [ConfigService]: Se han cargado " + cacheSettings.size() + " parámetros desde la tabla 'settings'.");
            
        } catch (SQLException e) {
            // Manejo de errores críticos de conectividad o inconsistencia de esquema
            System.err.println("CRÍTICO [ConfigService]: Error al inicializar parámetros desde la tabla 'settings'.");
            e.printStackTrace();
        }
    }

    /**
     * Recupera el valor de una configuración específica.
     * * @param clave El nombre del parámetro (ej: 'email_user').
     * @return El valor asociado o null si la clave no existe.
     */
    public String getValor(String clave) {
        if (clave == null) return null;
        return cacheSettings.get(clave);
    }

    /**
     * Recupera un valor de configuración permitiendo definir un respaldo (fallback).
     * * @param clave El nombre del parámetro.
     * @param valorPorDefecto Valor a devolver si la clave no se encuentra en la BD.
     * @return El valor recuperado o el respaldo proporcionado.
     */
    public String getOrDefault(String clave, String valorPorDefecto) {
        String valor = cacheSettings.get(clave);
        return (valor != null) ? valor : valorPorDefecto;
    }

    /**
     * Verifica si una configuración específica está presente en el sistema.
     * * @param clave El nombre del parámetro a comprobar.
     * @return true si la clave existe en la caché.
     */
    public boolean contieneClave(String clave) {
        return cacheSettings.containsKey(clave);
    }
}