package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;
import java.io.IOException;

@WebServlet("/CambiarContrasenaServlet")
public class CambiarContrasenaServlet extends HttpServlet {

    //validar requisitos contraseña
    private static final String PASSWORD_REGEX = "^(?=.*[0-9])(?=.*[a-zA-Z]).{8}$";

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String accion = request.getParameter("accion");

        if (accion == null) {
            response.sendRedirect("login.jsp");
            return;
        }

        switch (accion) {
            case "enviarOTP":
                enviarOTPRecuperacion(request, response);
                break;

            case "cambiarContrasena":
                cambiarContrasena(request, response);
                break;

            default:
                response.sendRedirect("login.jsp");
        }
    }

 
    //enviar OTP de recuperación
 
    private void enviarOTPRecuperacion(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String dni = request.getParameter("dni");
        String correo = request.getParameter("correo");

        if (dni == null || correo == null || dni.isEmpty() || correo.isEmpty()) {
            request.setAttribute("error", "Campos obligatorios");
            request.getRequestDispatcher("recuperarContrasena.jsp").forward(request, response);
            return;
        }

        Usuario usuario = UsuarioDAO.obtenerUsuarioPorDNI(dni);
        if (usuario == null || !correo.equals(usuario.getCorreo())) {
            request.setAttribute("error", "DNI o correo incorrectos");
            request.getRequestDispatcher("recuperarContrasena.jsp").forward(request, response);
            return;
        }

        //generar OTP
        String otp = Correo.generaOTP();

        //guardar en sesión para que OTPServlet lo valide
        HttpSession sesion = request.getSession();
        sesion.setAttribute("recuperacion", true);
        sesion.setAttribute("otpRecuperacion", otp);
        sesion.setAttribute("emailRecuperacion", correo);
        sesion.setAttribute("dniRecuperacion", dni);

        //enviar correo
        Correo.enviaCorreo(correo, otp);

        //redirigir al JSP de verificación
        response.sendRedirect("verificaOTP.jsp");
    }

    //cambiar contraseña (OTP ya validado)
 
    private void cambiarContrasena(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        HttpSession sesion = request.getSession(false);
        if (sesion == null || sesion.getAttribute("dniRecuperacion") == null) {
            response.sendRedirect("login.jsp");
            return;
        }

        String nuevaContrasena = request.getParameter("nuevaContrasena");
        String repetirContrasena = request.getParameter("repetirContrasena");
        String dni = (String) sesion.getAttribute("dniRecuperacion");

        if (nuevaContrasena == null || repetirContrasena == null || nuevaContrasena.isEmpty() || repetirContrasena.isEmpty()) {
            request.setAttribute("error", "Debe completar ambos campos de contraseña.");
            request.getRequestDispatcher("cambiarContrasena.jsp").forward(request, response);
            return;
        }

        //validar que cumpla los requisitos
        if (!nuevaContrasena.matches(PASSWORD_REGEX)) {
            request.setAttribute("error", "La contraseña debe tener exactamente 8 caracteres y contener al menos una letra y un número.");
            request.getRequestDispatcher("cambiarContrasena.jsp").forward(request, response);
            return;
        }

        //verificar que coincidan
        if (!nuevaContrasena.equals(repetirContrasena)) {
            request.setAttribute("error", "Las contraseñas no coinciden.");
            request.getRequestDispatcher("cambiarContrasena.jsp").forward(request, response);
            return;
        }

        Usuario usuario = UsuarioDAO.obtenerUsuarioPorDNI(dni);
        if (usuario == null) {
            response.sendRedirect("login.jsp");
            return;
        }

        //actualizar contraseña en la base de datos
        UsuarioDAO.actualizarContrasena(usuario.getCorreo(), nuevaContrasena);

        //limpiar las variables de sesión
        sesion.removeAttribute("recuperacion");
        sesion.removeAttribute("dniRecuperacion");
        sesion.removeAttribute("emailRecuperacion");
        sesion.removeAttribute("otpRecuperacion");

        //redirigir a login
        response.sendRedirect("login.jsp");
    }
}
