package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;

import java.io.IOException;
import org.json.JSONObject;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.io.InputStream;

@WebServlet("/LoginServlet")
public class LoginServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String dni = request.getParameter("dni");
        String contrasena = request.getParameter("contrasena");

        String latitud = request.getParameter("latitud");
        String longitud = request.getParameter("longitud");

        if (dni == null || dni.isEmpty() || contrasena == null || contrasena.isEmpty()) {
            request.setAttribute("error", "Rellene los campos.");
            request.getRequestDispatcher("login.jsp").forward(request, response);
            return;
        }

        //obtener usuario mediante DAO
        Usuario usuario = UsuarioDAO.obtenerUsuarioPorDNI(dni);

        if (usuario == null || !usuario.getContrasena().equals(contrasena)) {
            request.setAttribute("error", "DNI o contraseña incorrectos");
            request.getRequestDispatcher("login.jsp").forward(request, response);
            return;
        }


        //validacion por ip
        String ipActual = getClientIp(request);
        if (usuario.getIpPermitida() == null || usuario.getIpPermitida().isEmpty()) {
            //registrar primera IP
            usuario.setIpPermitida(ipActual);
            UsuarioDAO.actualizarIpPermitida(dni, ipActual);

        } 
        else if (!usuario.getIpPermitida().equals(ipActual)) {
            request.setAttribute("error",
                    "Acceso denegado: IP no autorizada (" + ipActual + ")");
            request.getRequestDispatcher("login.jsp").forward(request, response);
            return;
        }

        //valida ubicacion

        if (latitud == null || longitud == null || latitud.isEmpty() || longitud.isEmpty()) {
            request.setAttribute("error", "No se pudo obtener la ubicación del dispositivo.");
            request.getRequestDispatcher("login.jsp").forward(request, response);
            return;
        }

        double latActual = Double.parseDouble(latitud);
        double lonActual = Double.parseDouble(longitud);

        if (usuario.getLatPermitida() == null || usuario.getLonPermitida() == null ||
                (usuario.getLatPermitida() == 0 && usuario.getLonPermitida() == 0)) {

            //registrar primera ubicación
            usuario.setLatPermitida(latActual);
            usuario.setLonPermitida(lonActual);
            UsuarioDAO.actualizarUbicacionPermitida(dni, latActual, lonActual);

        } 
        else {
            double distancia = calcularDistancia(
                    latActual, lonActual,
                    usuario.getLatPermitida(), usuario.getLonPermitida()
            );

            if (distancia > 20) {
                request.setAttribute("error",
                        "Acceso denegado: estás a " + String.format("%.2f", distancia) +
                                " km de tu ubicación permitida.");
                request.getRequestDispatcher("login.jsp").forward(request, response);
                return;
            }
        }

        //enviar otp al correo
        String correo = usuario.getCorreo();

        if (correo == null) {
            request.setAttribute("error", "No se encontró correo registrado para este usuario.");
            request.getRequestDispatcher("login.jsp").forward(request, response);
            return;
        }

        String otp = Correo.generaOTP();

        HttpSession sesion = request.getSession();
        sesion.setAttribute("otp", otp);
        sesion.setAttribute("usuarioTemp", dni);

        Correo.enviaCorreo(correo, otp);

      
        //registrar ip
        String pais = "Desconocido";
        String ciudad = "Desconocida";

        try {
            JSONObject json = consultarIP(ipActual);
            pais = json.optString("country", "Desconocido");
            ciudad = json.optString("city", "Desconocida");
        } catch (Exception ignored) {}

        UsuarioDAO.registrarAccesoIP(dni, ipActual, pais, ciudad);

        response.sendRedirect("verificaOTP.jsp");
    }


    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        request.getRequestDispatcher("login.jsp").forward(request, response);
    }

    private String getClientIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        return (xf != null && !xf.isEmpty()) ? xf.split(",")[0] : request.getRemoteAddr();
    }

    private JSONObject consultarIP(String ip) throws IOException {
        String urlStr = "http://ip-api.com/json/" + URLEncoder.encode(ip, StandardCharsets.UTF_8);
        HttpURLConnection con = (HttpURLConnection) new URL(urlStr).openConnection();

        try (InputStream in = con.getInputStream()) {
            return new JSONObject(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    public static double calcularDistancia(double lat1, double lon1, double lat2, double lon2) {
        double R = 6371;
        double dLat = Math.toRadians(lat2 - lat1);
        double dLon = Math.toRadians(lon2 - lon1);

        double a = Math.sin(dLat / 2) * Math.sin(dLat / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                * Math.sin(dLon / 2) * Math.sin(dLon / 2);

        return R * (2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)));
    }
}
