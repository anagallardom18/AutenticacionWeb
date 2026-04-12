<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Configurar TOTP - Acceso Seguro</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/estilos.css?v=2">
</head>

<body>

<div class="login-container">

    <div class="login-card">
        <h2>Configurar TOTP</h2>

        <% if (request.getAttribute("error") != null) { %>
            <div class="error-msg">
                <%= request.getAttribute("error") %>
            </div>
        <% } %>

        <div class="text-center">
            <h3>1. Escanee el código QR</h3>
            <p class="text-muted">Use una aplicación de autenticación en su móvil.</p>
            
            <div class="qr-container">
                <img src="<%= request.getAttribute("qrUrl") %>"
                     alt="Código QR de configuración"
                     class="qr-img">
            </div>
        </div>

        <div class="margin-top-md">
            <h3>2. Configuración manual</h3>
            <p class="text-muted">Si no puede escanear, introduzca este código:</p>
            <input type="text"
                   class="input-otp"
                   value="<%= request.getAttribute("secret") %>"
                   readonly>
        </div>

        <div class="margin-top-md">
            <h3>3. Verificación</h3>
            <p class="text-muted">Introduzca el código generado para activar.</p>

            <form action="RegistroTOTPServlet" method="post">
                <input type="text"
                       name="codigo"
                       class="input-otp"
                       placeholder="000000"
                       maxlength="6"
                       required
                       pattern="[0-9]{6}"
                       autofocus>
                
                <button type="submit" class="btn-primary">Activar Protección</button>
            </form>
        </div>
    </div>

 	<div class="footer-actions">
        <a href="bienvenido.jsp" class="btn-secondary">Volver a la página del usuario</a>
    </div>
    
    <div class="footer-actions">
        <a href="index.jsp" class="btn-secondary">Volver al inicio</a>
      
    </div>
   

</div>

</body>
</html>
