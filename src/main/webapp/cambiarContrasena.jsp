<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%
    // Verificación de seguridad: si no hay DNI en sesión, redirigir
    String dni = null;
    if (session.getAttribute("dniRecuperacion") != null) {
        dni = (String) session.getAttribute("dniRecuperacion");
    } else if (session.getAttribute("usuarioTemp") != null) {
        dni = (String) session.getAttribute("usuarioTemp");
    } else {
        response.sendRedirect("index.jsp");
        return;
    }
    response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
%>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Cambiar Contraseña - Acceso Seguro</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/estilos.css?v=2">
</head>
<body>

<div class="login-container">

    <div class="login-card">
        <h2>Nueva Contraseña</h2>
        
        <p class="text-center text-muted">
            Actualización de credenciales para el usuario: <strong><%= dni %></strong>
        </p>

        <% if (request.getAttribute("error") != null) { %>
            <div class="error-msg">
                <%= request.getAttribute("error") %>
            </div>
        <% } %>

        <% if (request.getAttribute("mensaje") != null) { %>
            <div class="success-msg">
                <%= request.getAttribute("mensaje") %>
            </div>
        <% } %>

        <form action="CambiarContrasenaServlet" method="post">
            <input type="hidden" name="accion" value="cambiarContrasena">
            <input type="hidden" name="dni" value="<%= dni %>">

            <label for="nuevaContrasena">Nueva contraseña:</label>
            <input type="password" name="nuevaContrasena" id="nuevaContrasena" required autofocus>
            
            <label for="repetirContrasena">Confirme la contraseña:</label>
            <input type="password" name="repetirContrasena" id="repetirContrasena" required>

            <button type="submit" class="btn-primary">Actualizar Credenciales</button>
        </form>
    </div>

    <div class="footer-actions">
        <a href="login1fa.jsp" class="btn-secondary">Volver al inicio de sesión</a>
    </div>

</div>

</body>
</html>