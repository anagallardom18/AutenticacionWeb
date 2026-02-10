package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;
import java.io.IOException;

@WebServlet("/RegistroServlet")
public class RegistroServlet extends HttpServlet {

    private static final String PASSWORD_REGEX = "^(?=.*[0-9])(?=.*[a-zA-Z]).{8}$";
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
    	
        String dni = request.getParameter("dni");
        String correo = request.getParameter("correo");
        String contrasena = request.getParameter("contrasena");
        String contrasena2 = request.getParameter("contrasena2");

        if (dni == null || correo == null || contrasena == null || contrasena2 == null ||
            dni.isEmpty() || correo.isEmpty() || contrasena.isEmpty() || contrasena2.isEmpty()) {

            request.setAttribute("error", "Todos los campos son obligatorios.");
            request.getRequestDispatcher("registro.jsp").forward(request, response);
            return;
        }

        
  
        if (!contrasena.matches(PASSWORD_REGEX)) {
            request.setAttribute("error", "La contraseña debe tener exactamente 8 caracteres y contener al menos una letra y al menos un número.");
            
            //mantener el DNI y el correo al regresar al formulario
            request.setAttribute("dni", dni); 
            request.setAttribute("correo", correo);
            
            request.getRequestDispatcher("registro.jsp").forward(request, response);
            return;
        }
        
        
        if (!contrasena.equals(contrasena2)) {
            request.setAttribute("error", "Las contraseñas no coinciden.");
            request.getRequestDispatcher("registro.jsp").forward(request, response);
            return;
        }

        //dni no registrado
        Usuario existente = UsuarioDAO.obtenerUsuarioPorDNI(dni);
        if (existente != null) {
            request.setAttribute("error", "Ya existe un usuario con ese DNI.");
            request.getRequestDispatcher("registro.jsp").forward(request, response);
            return;
        }

     
        Usuario nuevo = new Usuario();
        nuevo.setDni(dni);
        nuevo.setCorreo(correo);
        nuevo.setContrasena(contrasena);
        nuevo.setIpRegistro(null);
        nuevo.setUbicacion(null);

        //registrar en base de datos
        UsuarioDAO.registrarUsuario(nuevo);

        response.sendRedirect("login.jsp");
    }
}
