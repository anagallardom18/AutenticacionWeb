<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%
  // 1. Verificación de sesión de seguridad
  if (session.getAttribute("usuarioTemp") == null && session.getAttribute("dniRecuperacion") == null) {
    response.sendRedirect("index.jsp");
    return;
  }
  // 2. Seguridad de caché
  response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
%>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Verificación OTP - Acceso Seguro</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/estilos.css?v=3">
</head>
<body>

<div class="login-container">
    <div class="login-card">
        <h2>Verificación de Seguridad</h2>
        
        <p class="instrucciones-otp">
            Introduzca el código enviado a su correo electrónico.
        </p>

        <%-- Mensaje de error --%>
        <% if (request.getAttribute("error") != null) { %>
            <div class="error-msg">
                <%= request.getAttribute("error") %>
            </div>
        <% } %>

        <form action="OTPServlet" method="post">
            <div class="form-group">
                <label for="otp">Código OTP:</label>
                <input type="text" name="otp" id="otp" class="input-otp" 
                       placeholder="000000" maxlength="6" required autofocus>
            </div>
            <button type="submit" class="btn-primary">Verificar y Acceder</button>
        </form>

        <%-- Alternativas de acceso --%>
        <div class="selector-alternativo">
            <p>¿No puede acceder a su correo?</p>
            <div class="links-alternativos">
                <a href="loginAlternativo.jsp" class="link-seguro">Probar de otra manera</a>
            </div>
        </div>

    </div> 
    
    <div class="footer-actions">
        <a href="index.jsp" class="btn-secondary">Cancelar proceso</a>
    </div>
</div> 

</body>
</html>