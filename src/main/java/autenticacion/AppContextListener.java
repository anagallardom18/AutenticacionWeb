package autenticacion;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import com.mysql.cj.jdbc.AbandonedConnectionCleanupThread;

/**
 * Listener del ciclo de vida de la aplicación.
 * Se encarga de gestionar eventos de inicio y cierre del servidor web.
 */
@WebListener
public class AppContextListener implements ServletContextListener {

    /**
     * Este método se ejecuta automáticamente cuando la aplicación se detiene
     */
    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        try {
            /*
             * MySQL Connector/J crea hilos internos para limpiar conexiones abandonadas.
             * Si no se detienen manualmente al cerrar la app, pueden causar Memory Leaks 
             * y errores de "hilos colgados" en el servidor.
             */
            AbandonedConnectionCleanupThread.checkedShutdown();
            System.out.println("INFO: Hilos de limpieza de MySQL detenidos correctamente.");
            
        } catch (Exception e) {
            // Si hay un error al cerrar los hilos se imprime en el log del servidor
            System.err.println("ERROR: No se pudieron detener los hilos de MySQL.");
            e.printStackTrace();
        }
    }

    /**
     * Este método se ejecuta cuando la aplicación se inicia.
     */
    @Override
    public void contextInitialized(ServletContextEvent sce) {
        System.out.println("INFO: Aplicación de Autenticación iniciada.");
    }
}