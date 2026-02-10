<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>

<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Registro de Usuario</title>
<link rel="stylesheet" href="<%= request.getContextPath() %>/css/estilos.css">
</head>
<body>

<div class="login-container">
    <div class="login-card">
        <h2>Registro de Usuario</h2>

        <% if (request.getAttribute("error") != null) { %>
            <p class="error-msg"><%= request.getAttribute("error") %></p>
        <% } %>

        <form id="registroForm" action="RegistroServlet" method="post">
            <label>DNI:</label>
            <input type="text" name="dni" id="dniRegistro"
                   value="<%= request.getAttribute("dni") != null ? request.getAttribute("dni") : "" %>" required>

            <label>Correo electrónico:</label>
            <input type="email" name="correo" id="correoRegistro"
                   value="<%= request.getAttribute("correo") != null ? request.getAttribute("correo") : "" %>" required>

            <label>Contraseña:</label>
            <input type="password" name="contrasena" id="contrasena" required>

            <label>Confirmar contraseña:</label>
            <input type="password" name="contrasena2" id="contrasena2" required>

            <button type="submit" class="btn-primary">Registrarse</button>
        </form>

        <p class="register-text">
            ¿Ya tienes cuenta? <a href="login.jsp">Inicia sesión aquí</a>
        </p>
    </div>
</div>

<script>
	
	document.getElementById("registroForm").addEventListener("submit", function(e) {
	    const pass1 = document.getElementById("contrasena").value;
	    const pass2 = document.getElementById("contrasena2").value;
	
	    if(pass1 !== pass2) {
	        e.preventDefault(); //evita enviar el formulario
	        alert("Las contraseñas no coinciden.");
	        document.getElementById("contrasena2").focus();
	    }
	});
</script>

</body>
</html>
