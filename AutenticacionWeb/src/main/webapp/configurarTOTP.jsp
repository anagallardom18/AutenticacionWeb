<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Configurar TOTP</title>
    <link rel="stylesheet" href="css/estilos.css">
</head>

<body>

<div class="login-container">

    <div class="login-card">

        <h2>Configurar Autenticación TOTP</h2>

        <!-- Mostrar error -->
        <% if (request.getAttribute("error") != null) { %>
            <div class="error-msg">
                <%= request.getAttribute("error") %>
            </div>
        <% } %>

        <!-- QR -->
        <h3>1. Escanea este código QR con Google Authenticator</h3>
        <img src="<%= request.getAttribute("qrUrl") %>"
             alt="Código QR"
             class="qr-img">

        <!-- Código secreto -->
        <h3>2. O introduce este código manualmente</h3>
        <input type="text"
               class="readonly-code"
               value="<%= request.getAttribute("secret") %>"
               readonly>

        <!-- Validar TOTP -->
        <h3>3. Ingresa un código de 6 dígitos para activar</h3>

        <form action="ConfigurarTOTPServlet" method="post">
            <input type="text"
                   name="codigo"
                   placeholder="Código TOTP"
                   maxlength="6"
                   required
                   pattern="[0-9]{6}"
                   title="Introduce un código de 6 dígitos">
            <button type="submit" class="btn-primary">Activar TOTP</button>
        </form>

        <div class="register-text">
            <a href="login.jsp">Volver al login</a>
        </div>

    </div>

</div>

</body>
</html>

