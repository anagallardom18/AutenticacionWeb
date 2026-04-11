<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.util.List" %>
<%@ page import="java.util.ArrayList" %>
<%
    response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");

    List<String> superadas = (List<String>) session.getAttribute("categoriasSuperadas");
    if (superadas == null) superadas = new ArrayList<>();

    boolean yaSabe = superadas.contains("SABER"); 
    boolean yaTiene = superadas.contains("TENER"); 
    boolean yaEs = superadas.contains("SER");     

    String dniTemporal = (String) request.getAttribute("dniRecordado");
    if (dniTemporal == null) dniTemporal = (String) session.getAttribute("usuarioTemp");
    if (dniTemporal == null) dniTemporal = (String) session.getAttribute("webauthn_dni");
    if (dniTemporal == null) dniTemporal = "";
%>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Acceso Alternativo - Seguridad</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/estilos.css?v=2">
</head>
<body>

<div class="login-container">
    
    <%-- Info de Identidad --%>
    <div class="login-card info-card">
        <p>
            <strong>Verificación de Seguridad</strong><br>
            Identidad: <span class="highlight-text"><%= dniTemporal.isEmpty() ? "No identificada" : dniTemporal %></span>
        </p>
    </div>

    <% if (request.getAttribute("error") != null) { %>
        <div class="error-msg">
            <%= request.getAttribute("error") %>
        </div>
    <% } %>

    <%-- CATEGORÍA: ALGO QUE SABE (CONOCIMIENTO) --%>
    <% if (!yaSabe) { %>
        <div class="login-card">
            <h3>Factor Conocimiento</h3>
            <form action="LoginServlet" method="post">
                <input type="hidden" name="dni" value="<%= dniTemporal %>">
                <input type="hidden" name="modoLogin" value="2FA">
                
                <label for="contrasena">Contraseña:</label>
                <input type="password" name="contrasena" id="contrasena" required autofocus>
                
                <button type="submit" class="btn-primary">Verificar Contraseña</button>
            </form>
        </div>
    <% } %>

    <%-- CATEGORÍA: ALGO QUE TIENE (POSESIÓN) --%>
    <% if (!yaTiene) { %>
        <div class="login-card">
            <h3>Factor Posesión</h3>
            
            <form action="LoginTOTPServlet" method="post" class="margin-bottom-sm">
                <input type="hidden" name="dni" value="<%= dniTemporal %>">
                <input type="hidden" name="modoLogin" value="2FA">
                <label for="totp">Código TOTP:</label>
                <input type="text" name="totp" id="totp" class="input-otp" required placeholder="000000" maxlength="6">
                <button type="submit" class="btn-primary">Validar Código</button>
            </form>

            <div class="separator-text">O BIEN</div>

            <input type="hidden" id="dniFIDO2" value="<%= dniTemporal %>">
            <button type="button" id="btnFIDO2" class="btn-secondary">
                Usar Llave FIDO2
            </button>
        </div>
    <% } %>

    <%-- CATEGORÍA: ALGO QUE ES (INHERENCIA) --%>
    <% if (!yaEs) { %>
        <div class="login-card">
            <h3>Factor Inherencia</h3>
            
            <input type="hidden" id="dniBiometria" value="<%= dniTemporal %>">
            <input type="hidden" id="dniPasskey" value="<%= dniTemporal %>">

            <button type="button" id="btnBiometria" class="btn-primary margin-bottom-sm">
                Autenticación Biométrica
            </button>
             <div class="separator-text">O BIEN</div>
            
            <button type="button" id="btnPasskey" class="btn-secondary">
                Acceder con Passkey
            </button>
        </div>
    <% } %>

    <div class="footer-actions">
        <a href="index.jsp" class="btn-secondary">Volver al inicio</a>
    </div>

</div>

<script>
    const contextPath = '<%= request.getContextPath() %>';
    const globalModoLogin = "2FA";
</script>
<script src="<%= request.getContextPath() %>/js/login.js"></script>

</body>
</html>