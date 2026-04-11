package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;
import java.io.IOException;


/**
 * Servlet encargado de cerrar sesión
 */
@WebServlet("/LogoutServlet")
public class LogoutServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
        // 1. Obtener la sesión actual sin crear una nueva
        HttpSession sesion = request.getSession(false); 
        
        if (sesion != null) {
            // 2. Limpiar todos los atributos y destruir la sesión en el servidor
            sesion.invalidate();
        }
        
       
        // limpia la caché del navegador para la respuesta de redirección
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate"); // HTTP 1.1
        response.setHeader("Pragma", "no-cache"); // HTTP 1.0
        response.setDateHeader("Expires", 0); // Proxies

        // 4. Redirigir al inicio o al login
        response.sendRedirect("index.jsp");
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // Por seguridad, permitimos que el logout también funcione por POST
        doGet(request, response);
    }
}