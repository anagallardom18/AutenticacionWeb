<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Registro de Usuario - Acceso Seguro</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/estilos.css?v=2">
</head>
<body>

<div class="login-container">
    <div class="login-card">
        <h2>Registro de Usuario</h2>

        <% if (request.getAttribute("error") != null) { %>
            <div class="error-msg">
                <%= request.getAttribute("error") %>
            </div>
        <% } %>

        <form id="registroForm" action="RegistroServlet" method="post">
            <label for="dniRegistro">DNI:</label>
            <input type="text" name="dni" id="dniRegistro"
                   value="<%= request.getAttribute("dni") != null ? request.getAttribute("dni") : "" %>" 
                   placeholder="12345678X" required autofocus>

            <label for="correoRegistro">Correo electrónico:</label>
            <input type="email" name="correo" id="correoRegistro"
                   value="<%= request.getAttribute("correo") != null ? request.getAttribute("correo") : "" %>" 
                   placeholder="ejemplo@correo.com" required>

            <label for="contrasena">Contraseña:</label>
            <input type="password" name="contrasena" id="contrasena" required>

            <label for="contrasena2">Confirmar contraseña:</label>
            <input type="password" name="contrasena2" id="contrasena2" required>

            <button type="submit" class="btn-primary">Registrarse</button>
        </form>

        <p class="text-center margin-top-md">
            ¿Ya tienes cuenta? <a href="login1fa.jsp" class="btn-link">Inicia sesión aquí</a>
        </p>
    </div>
    
    <div class="footer-actions">
        <a href="index.jsp" class="btn-secondary">Volver al inicio</a>
    </div>
</div>

<script src="<%= request.getContextPath() %>/js/registro.js"></script>

</body>
</html>