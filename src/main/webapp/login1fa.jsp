<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.util.List" %>
<%@ page import="java.util.ArrayList" %>
<%
    // Evitar caché para que no se queden datos viejos en el formulario
    response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");

    List<String> superadas = (List<String>) session.getAttribute("categoriasSuperadas");
    if (superadas == null) superadas = new ArrayList<>();
    
    // BÚSQUEDA EXHAUSTIVA DEL DNI
    String dniRec = (String) request.getAttribute("dniRecordado");
    if (dniRec == null) dniRec = (String) session.getAttribute("usuarioTemp");
    if (dniRec == null) dniRec = "";
%>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Inicio de Sesión - Acceso Seguro</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
  
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/estilos.css?v=2">
</head>
<body>

<div class="login-container">
    
    <div class="login-header">
        <h1>Identificación de Usuario</h1>
        <p>Seleccione su método de acceso para entrar al sistema</p>
    </div>

   
    <% if (request.getAttribute("error") != null) { %>
        <div class="error-msg">
            <%= request.getAttribute("error") %>
        </div>
    <% } %>

    <%-- 1. INICIO DE SESIÓN CON CONTRASEÑA --%>
    <% if (request.getAttribute("bloqueoMFA") == null) { %>
        <div class="login-card">
            <h3>Inicio de sesión con contraseña</h3>
            <form action="LoginServlet" method="post">
                <input type="hidden" name="modoLogin" value="1FA">
                
                <label for="dni">DNI:</label>
                <input type="text" name="dni" id="dni" value="<%= dniRec %>" required placeholder="12345678X" autofocus>

                <label for="contrasena">Contraseña:</label>
                <input type="password" name="contrasena" id="contrasena" required>

                <p class="forgot-password"><a href="recuperarContrasena.jsp">¿Olvidaste tu contraseña?</a></p>

                <button type="submit" class="btn-primary">Validar contraseña</button>
                
                <input type="hidden" id="latitud" name="latitud">
                <input type="hidden" id="longitud" name="longitud">
            </form>
        </div>
    <% } else { %>
      
        <div class="login-card card-error">
            <h3>Acceso bloqueado</h3>
            <p>Demasiados intentos fallidos con contraseña. Utilice un método biométrico o de posesión.</p>
        </div>
    <% } %>

    <%-- 2. INICIO DE SESIÓN CON TOTP --%>
    <div class="login-card">
        <h3>Inicio de sesión con código TOTP</h3>
        <form action="LoginTOTPServlet" method="post">
            <input type="hidden" name="modoLogin" value="1FA">
            <label>DNI:</label>
            <input type="text" name="dni" value="<%= dniRec %>" required placeholder="12345678X">
            <label>Código de Aplicación (6 dígitos):</label>
            <input type="text" name="totp" class="input-otp" placeholder="000000" maxlength="6" required>
            <button type="submit" class="btn-primary">Validar TOTP</button>
        </form>
    </div>

    <%-- 3. INICIO DE SESIÓN CON FIDO2 --%>
    <div class="login-card">
        <h3>Inicio de sesión con llave de física</h3>
        <label>DNI:</label>
        <input type="text" id="dniFIDO2" value="<%= dniRec %>" placeholder="12345678X" required>
        <button type="button" id="btnFIDO2" class="btn-primary">Usar Llave Física</button>
    </div>

    <%-- 4. INICIO DE SESIÓN CON BIOMETRÍA --%>
    <div class="login-card">
        <h3>Inicio de sesión biométrica</h3>
        <label>DNI:</label>
        <input type="text" id="dniBiometria" value="<%= dniRec %>" placeholder="12345678X" required>
        <button type="button" id="btnBiometria" class="btn-primary">Escanear Huella/Rostro</button>
    </div>

    <%-- 5. INICIO DE SESIÓN CON PASSKEY --%>
    <div class="login-card">
        <h3>Inicio de sesión con Passkey</h3>
        <label>DNI:</label>
        <input type="text" id="dniPasskey" value="<%= dniRec %>" placeholder="12345678X" required>
        <button type="button" id="btnPasskey" class="btn-primary">Acceder con Passkey</button>
    </div>

    <p class="register-text">
        ¿No tienes cuenta? <a href="registro.jsp">Regístrate aquí</a>
    </p>

    <div class="footer-actions">
        <a href="index.jsp" class="btn-secondary">Volver al inicio</a>
    </div>
</div>

<script>
    const contextPath = '<%= request.getContextPath() %>';
    const globalModoLogin = "1FA";
</script>
<script src="<%= request.getContextPath() %>/js/login1fa.js"></script>

</body>
</html>