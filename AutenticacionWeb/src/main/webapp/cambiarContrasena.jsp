<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8" %>
<%
    String dni = null;
    if (session.getAttribute("dniRecuperacion") != null) {
        dni = (String) session.getAttribute("dniRecuperacion");
    } else if (session.getAttribute("usuarioTemp") != null) {
        dni = (String) session.getAttribute("usuarioTemp");
    } else {
        response.sendRedirect("login.jsp");
        return;
    }
%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Cambiar Contraseña</title>
<link rel="stylesheet" href="css/estilos.css">
</head>
<body>

<div class="login-container">

    <div class="login-card">
        <h2>Cambiar Contraseña</h2>

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

            <input type="password" name="nuevaContrasena" placeholder="Nueva contraseña" required>
            <input type="password" name="repetirContrasena" placeholder="Repetir contraseña" required>

            <button type="submit" class="btn-primary">Cambiar contraseña</button>
        </form>
    </div>

    <div class="login-card">
        <div class="register-text">
            <a href="login.jsp">Volver al login</a>
        </div>
    </div>

</div>

</body>
</html>
