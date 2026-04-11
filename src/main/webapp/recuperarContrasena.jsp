<%@ page contentType="text/html; charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Recuperar Contraseña - Acceso Seguro</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/estilos.css?v=2">
</head>
<body>

<div class="login-container">

    <div class="login-card">
        <h2>Recuperar Contraseña</h2>
        
        <p class="text-center text-muted">
            Introduzca sus datos para recibir un código de verificación.
        </p>

        <% if (request.getAttribute("error") != null) { %>
            <div class="error-msg">
                <%= request.getAttribute("error") %>
            </div>
        <% } %>

        <form action="CambiarContrasenaServlet" method="post">
            <input type="hidden" name="accion" value="enviarOTP">
            
            <label for="dni">DNI:</label>
            <input type="text" name="dni" id="dni" placeholder="12345678X" required autofocus>
            
            <label for="correo">Correo electrónico:</label>
            <input type="email" name="correo" id="correo" placeholder="ejemplo@correo.com" required>

            <button type="submit" class="btn-primary">Enviar código de recuperación</button>
        </form>
    </div>

    <div class="footer-actions">
        <a href="login1fa.jsp" class="btn-secondary">Volver al inicio de sesión</a>
    </div>

</div>

</body>
</html>