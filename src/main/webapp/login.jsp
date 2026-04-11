<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.util.List, java.util.ArrayList" %>
<%
    // Evitar que la página se guarde en caché por seguridad
    response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    
    List<String> superadas = (List<String>) session.getAttribute("categoriasSuperadas");
    if (superadas == null) superadas = new ArrayList<>();

    // REVISIÓN DE DNI: Recopilación de todas las fuentes posibles
    String dniRec = (String) request.getAttribute("dniRecordado");
    if (dniRec == null) dniRec = (String) session.getAttribute("usuarioTemp");
    if (dniRec == null) dniRec = (String) session.getAttribute("webauthn_dni");
    if (dniRec == null) dniRec = ""; 

    boolean mostrarInputDNI = dniRec.isEmpty();
    Object bloqueo = request.getAttribute("bloqueoMFA");
%>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Segunda Verificación - Acceso Seguro</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/estilos.css?v=2">
</head>
<body>

<div class="login-container">

    <div class="login-header">
        <h1>Verificación de Identidad</h1>
        <% if (mostrarInputDNI) { %>
            <p>Por favor, introduzca su DNI para validar el factor.</p>
        <% } else { %>
            <p>Usuario: <strong><%= dniRec %></strong> 
               <a href="index.jsp" class="link-cambiar"> (Cambiar usuario)</a>
            </p>
        <% } %>
    </div>

    <% if (request.getAttribute("error") != null) { %>
        <div class="error-msg">
            <%= request.getAttribute("error") %>
        </div>
    <% } %>

    <%-- --- MÉTODOS DE ACCESO --- --%>

    <%-- 1. CONTRASEÑA (SABER) --%>
    <% if (!superadas.contains("SABER")) { %>
        <% if (bloqueo == null) { %>
            <div class="login-card">
                <h3>Inicio de sesión con contraseña</h3>
                <form action="LoginServlet" method="post">
                    <input type="hidden" name="modoLogin" value="2FA">
                    
                    <label>DNI:</label>
                    <% if (mostrarInputDNI) { %>
                        <input type="text" name="dni" required placeholder="12345678X" autofocus>
                    <% } else { %>
                        <p><strong><%= dniRec %></strong></p>
                        <input type="hidden" name="dni" value="<%= dniRec %>">
                    <% } %>

                    <label>Contraseña:</label>
                    <input type="password" name="contrasena" required>
                    
                     <p class="forgot-password"><a href="recuperarContrasena.jsp">¿Olvidaste tu contraseña?</a></p>
                    <button type="submit" class="btn-primary">Validar Contraseña</button>
                    
                    <input type="hidden" id="latitud" name="latitud">
                    <input type="hidden" id="longitud" name="longitud">
                </form>
            </div>
        <% } else { %>
            <div class="login-card card-error">
                <h3>Acceso por contraseña bloqueado</h3>
                <p>Demasiados intentos fallidos. Use un método alternativo.</p>
            </div>
        <% } %>
    <% } %>

    <%-- 2. TOTP (TENER) --%>
    <% if (!superadas.contains("TENER")) { %>
        <div class="login-card">
            <h3>Inicio de sesión con TOTP</h3>
            <form action="LoginTOTPServlet" method="post">
                <input type="hidden" name="modoLogin" value="2FA">
                <label>DNI:</label>
                <% if (mostrarInputDNI) { %>
                    <input type="text" name="dni" required placeholder="12345678X">
                <% } else { %>
                    <p><strong><%= dniRec %></strong></p>
                    <input type="hidden" name="dni" value="<%= dniRec %>">
                <% } %>
                
                <label>Código de la APP:</label>
                <input type="text" name="totp" class="input-otp" placeholder="000000" required>
                <button type="submit" class="btn-primary">Validar TOTP</button>
            </form>
        </div>
    <% } %>

    <%-- 3. FIDO2 (TENER) --%>
    <% if (!superadas.contains("TENER")) { %>
        <div class="login-card">
            <h3>Inicio de sesión con llave física</h3>
            <% if (mostrarInputDNI) { %>
                <label>DNI:</label>
                <input type="text" id="dniFIDO2" placeholder="12345678X" required>
            <% } else { %>
                <input type="hidden" id="dniFIDO2" value="<%= dniRec %>">
            <% } %>
            <button type="button" id="btnFIDO2" class="btn-primary">Usar Llave de Seguridad</button>
        </div>
    <% } %>

    <%-- 4. BIOMETRÍA (SER) --%>
    <% if (!superadas.contains("SER")) { %>
        <div class="login-card">
            <h3>Inicio de sesión biométrica</h3>
            <% if (mostrarInputDNI) { %>
                <label>DNI:</label>
                <input type="text" id="dniBiometria" placeholder="12345678X" required>
            <% } else { %>
                <input type="hidden" id="dniBiometria" value="<%= dniRec %>">
            <% } %>
            <button type="button" id="btnBiometria" class="btn-primary">Escanear Huella/Rostro</button>
        </div>
    <% } %>

    <%-- 5. PASSKEY (SER) --%>
    <% if (!superadas.contains("SER")) { %>
        <div class="login-card">
            <h3>Inicio de sesión con Passkey</h3>
            <% if (mostrarInputDNI) { %>
                <label>DNI:</label>
                <input type="text" id="dniPasskey" placeholder="12345678X" required>
            <% } else { %>
                <input type="hidden" id="dniPasskey" value="<%= dniRec %>">
            <% } %>
            <button type="button" id="btnPasskey" class="btn-primary">Usar Passkey</button>
        </div>
    <% } %>


 <p class="register-text">
        ¿No tienes cuenta? <a href="registro.jsp">Regístrate aquí</a>
    </p>
    <div class="footer-actions">
        <a href="index.jsp" class="btn-secondary">Volver a inicio</a>
    </div>
</div>

<script>
    const contextPath = '<%= request.getContextPath() %>';
    const globalModoLogin = "2FA";
</script>
<script src="<%= request.getContextPath() %>/js/login.js"></script>

</body>
</html>