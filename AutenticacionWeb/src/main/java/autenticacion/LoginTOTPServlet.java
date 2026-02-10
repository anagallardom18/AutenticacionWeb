package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;
import java.io.IOException;

@WebServlet("/LoginTOTPServlet")
public class LoginTOTPServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String dni = request.getParameter("dni");
        String totp = request.getParameter("totp");

        if (dni == null || totp == null || dni.isEmpty() || totp.isEmpty()) {
            request.setAttribute("error", "Completa todos los campos");
            request.getRequestDispatcher("login.jsp").forward(request, response);
            return;
        }

        //obtener usuario desde DAO
        Usuario usuario = UsuarioDAO.obtenerUsuarioPorDNI(dni);
        if (usuario == null) {
            request.setAttribute("error", "Usuario no encontrado");
            request.getRequestDispatcher("login.jsp").forward(request, response);
            return;
        }

        if (usuario.getTotpSecret() == null || usuario.getTotpSecret().isEmpty()) {
            request.setAttribute("error", "TOTP no configurado para este usuario");
            request.getRequestDispatcher("login.jsp").forward(request, response);
            return;
        }

        //validar TOTP
        boolean valido;
        try {
            valido = TOTPUtils.validarCodigo(usuario.getTotpSecret(), totp);
        } catch (Exception e) {
            e.printStackTrace();
            request.setAttribute("error", "Error al validar el código TOTP");
            request.getRequestDispatcher("login.jsp").forward(request, response);
            return;
        }

        if (!valido) {
            request.setAttribute("error", "Código TOTP incorrecto");
            request.getRequestDispatcher("login.jsp").forward(request, response);
            return;
        }

        //generar OTP y enviarlo
        String correo = usuario.getCorreo();
        String otp = String.format("%06d", new java.util.Random().nextInt(1000000));
        HttpSession sesion = request.getSession();
        sesion.setAttribute("usuarioTemp", dni);
        sesion.setAttribute("otp", otp);

        Correo.enviaCorreo(correo, otp);

        //redirigir a verificaOTP.jsp
        response.sendRedirect("verificaOTP.jsp");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.sendRedirect("login.jsp");
    }
}

