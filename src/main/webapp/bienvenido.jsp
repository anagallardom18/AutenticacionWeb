<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="jakarta.servlet.http.HttpSession" %>
<%
    // Verificación de sesión
    String usuario = (session != null) ? (String) session.getAttribute("usuario") : null;
    if (usuario == null) {
        response.sendRedirect("index.jsp");
        return;
    }
%>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Bienvenido - Panel de Usuario</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/estilos.css">
</head>
<body>

<div class="login-container">
    <div class="login-card">
        <h2>Bienvenido, <%= usuario %></h2>
        <hr>

        <h3>Seguridad de la cuenta</h3>

        <div class="section-auth">
            <form action="RegistroTOTPServlet" method="get">
                <input type="hidden" name="dni" value="<%= usuario %>">
                <button type="submit" class="btn-primary">Registrar Authenticator (TOTP)</button>
            </form>
        </div>

        <br>

        <div class="section-auth">
            <button type="button" class="btn-primary" onclick="registrarBiometria('<%= usuario %>')">
                Registrar biometría
            </button>
        </div>

        <br>

        <div class="section-auth">
            <button type="button" class="btn-primary" onclick="registrarFIDO2('<%= usuario %>')">
                Registrar dispositivo FIDO2 (USB/NFC)
            </button>
        </div>
        
        <br>

        <div class="section-auth">
            <button type="button" class="btn-primary" onclick="registrarPasskey('<%= usuario %>')">
                Registrar Passkey
            </button>
        </div>

        <hr>

        <form action="LogoutServlet" method="get">
            <button type="submit" class="btn-secondary">Cerrar sesión</button>
        </form>
    </div>
</div>

<script>
   
    const contextPath = '<%= request.getContextPath() %>';
</script>

<script src="<%= request.getContextPath() %>/js/bienvenido.js"></script>

</body>
</html>