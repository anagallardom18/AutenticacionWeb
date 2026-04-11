package autenticacion;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import jakarta.servlet.annotation.WebServlet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;

import com.google.zxing.*;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import java.util.HashMap;
import java.util.Map;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.sql.DataSource;

/**
 * GENERADOR DINÁMICO DE CÓDIGOS QR (QRMovilServlet)
 * * Gestiona la integración móvil mediante rutas adaptativas:
 * 1. MODO REMOTO: Prioriza la URL configurada en la BD (ej. Ngrok).
 * 2. MODO LOCAL: Si la BD está vacía, detecta la IP del servidor para
 * permitir el acceso desde dispositivos en la misma red Wi-Fi.
 * * Facilita la autenticación permitiendo el acceso móvil inmediato 
 * tanto por internet como en red local.
 */
@WebServlet("/QRMovilServlet")
public class QRMovilServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    /**
     * Procesa la solicitud GET para generar y servir un código QR en formato Base64.
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        try {
         
            
         // Obtención de la URL para el código QR (Prioridad: BD > Dinámica)
            String urlDestino = "";
            
         // Configuración de la conexión y el DAO
            Context ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup("java:comp/env/jdbc/autenticacion");
            UsuarioDAO usuarioDAO = new UsuarioDAO(ds);
            
         // Intentamos obtener la URL de la base de datos
            String urlBD = usuarioDAO.obtenerUrlPublica(); 

            if (urlBD != null && !urlBD.trim().isEmpty()) {
                // Escenario A: Prioridad a la URL configurada en BD (para túneles Ngrok)
                urlDestino = urlBD + request.getContextPath() + "/index.jsp";
            } else {
                // Escenario B: Fallback dinámico si no hay configuración en BD
                String esquema = request.getScheme();
                String nombreServidor = request.getServerName();
                int puertoServidor = request.getServerPort();

                // Si se accede por localhost, traducimos a la IP local para permitir acceso desde el móvil
                if (nombreServidor.equalsIgnoreCase("localhost") || nombreServidor.equals("127.0.0.1")) {
                    try {
                        nombreServidor = java.net.InetAddress.getLocalHost().getHostAddress();
                    } catch (Exception e) {
                  
                    }
                }

               
                String puertoStr = (puertoServidor == 80 || puertoServidor == 443) ? "" : ":" + puertoServidor;
                urlDestino = esquema + "://" + nombreServidor + puertoStr + request.getContextPath() + "/index.jsp";
            }

            // Registro de la URL final para auditoría en consola
            System.out.println("URL generada para el código QR: " + urlDestino);

            // 2. Parámetros de configuración del motor de renderizado (Hints)
            // Se define el set de caracteres y un nivel de corrección de errores (M) para asegurar la legibilidad.
            Map<EncodeHintType, Object> hints = new HashMap<>();
            hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");
            hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
            hints.put(EncodeHintType.MARGIN, 1);

            // 3. Generación de la matriz de bits (BitMatrix) utilizando la librería ZXing
            QRCodeWriter qrWriter = new QRCodeWriter();
            BitMatrix matrix = qrWriter.encode(urlDestino, BarcodeFormat.QR_CODE, 250, 250, hints);

            // 4. Conversión de la matriz a flujo de imagen PNG en memoria
            // Se evita el uso de almacenamiento físico para mejorar la seguridad y la velocidad de respuesta.
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(matrix, "PNG", outputStream);

            // 5. Codificación de la imagen resultante en formato Base64
            // Permite embeber la imagen directamente en el HTML del cliente (Data URI scheme).
            String base64QR = Base64.getEncoder().encodeToString(outputStream.toByteArray());

            // 6. Inyección de atributos en el contexto de la solicitud y despacho a la vista
            request.setAttribute("qrImage", "data:image/png;base64," + base64QR);
            request.setAttribute("urlGenerada", urlDestino); 

            request.getRequestDispatcher("mostrarQR.jsp").forward(request, response);
            
        } catch (Exception e) {
        	 // Log de error y propagación de excepción controlada
            e.printStackTrace();
            throw new ServletException("Fallo en el servicio de generación de QR", e);
        }
    }
}