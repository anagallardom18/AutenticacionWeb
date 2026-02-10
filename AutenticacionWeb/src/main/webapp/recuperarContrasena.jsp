<%@ page contentType="text/html; charset=UTF-8" %>
<!DOCTYPE html>
<html>
<head>
    <title>Recuperar contraseña</title>
    <link rel="stylesheet" href="css/estilos.css">
</head>
<body>

<div class="login-container">

    <div class="login-card">
        <h2>Recuperar contraseña</h2>

        <% if (request.getAttribute("error") != null) { %>
            <div class="error-msg">
                <%= request.getAttribute("error") %>
            </div>
        <% } %>

    <form action="CambiarContrasenaServlet" method="post">
    <input type="hidden" name="accion" value="enviarOTP">
    <input type="text" name="dni" placeholder="DNI" required>
    <input type="email" name="correo" placeholder="Correo electrónico" required>

    <button type="submit" class="btn-primary">Enviar código</button>
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
