package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;
import java.io.IOException;

@WebServlet("/OTPServlet")
public class OTPServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        HttpSession sesion = request.getSession();
        String codigoIntroducido = request.getParameter("otp");

        //bandera para saber si es recuperación de contraseña
        Boolean esRecuperacion = (Boolean) sesion.getAttribute("recuperacion");

        if(esRecuperacion != null && esRecuperacion) {
            //flujo recuperación de contraseña
            String otpCorrecto = (String) sesion.getAttribute("otpRecuperacion");
            String emailRecuperacion = (String) sesion.getAttribute("emailRecuperacion");

            if(otpCorrecto == null || emailRecuperacion == null) {
                response.sendRedirect("recuperarContrasena.jsp");
                return;
            }

            if(codigoIntroducido != null && codigoIntroducido.equals(otpCorrecto)) {
                //redirigir a cambiar contraseña
                response.sendRedirect("cambiarContrasena.jsp");
            } else {
                request.setAttribute("error", "Código incorrecto. Pruebe de nuevo.");
                request.getRequestDispatcher("verificaOTP.jsp").forward(request, response);
            }

            //limpiar variables temporales
            sesion.removeAttribute("otpRecuperacion");
            sesion.removeAttribute("emailRecuperacion");
            sesion.removeAttribute("recuperacion");

        } else {
            //flujo 2FA normal al iniciar sesión
            String otpCorrecto = (String) sesion.getAttribute("otp");
            String usuarioTemp = (String) sesion.getAttribute("usuarioTemp");

            if(otpCorrecto == null || usuarioTemp == null) {
                response.sendRedirect("login.jsp");
                return;
            }

            if(codigoIntroducido != null && codigoIntroducido.equals(otpCorrecto)) {
                sesion.setAttribute("usuario", usuarioTemp);

                //limpiar variables temporales
                sesion.removeAttribute("otp");
                sesion.removeAttribute("usuarioTemp");

                //redirigir a la página principal
                response.sendRedirect("bienvenido.jsp");
            } else {
                request.setAttribute("error", "Código incorrecto. Pruebe de nuevo.");
                request.getRequestDispatcher("verificaOTP.jsp").forward(request, response);
            }
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        //evitar el acceso directo por GET
        response.sendRedirect("login.jsp");
    }
}
