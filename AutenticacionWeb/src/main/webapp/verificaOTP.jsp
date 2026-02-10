<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%
  if (session.getAttribute("usuarioTemp") == null && session.getAttribute("dniRecuperacion") == null) {
    response.sendRedirect("login.jsp");
    return;
  }
%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Verificación OTP</title>
<link rel="stylesheet" href="<%= request.getContextPath() %>/css/estilos.css">
</head>
<body>

<div class="login-container">
    <div class="login-card">

        <h2>Introduzca el código enviado a su correo</h2>

        <% if (request.getAttribute("error") != null) { %>
            <p class="error-msg"><%= request.getAttribute("error") %></p>
        <% } %>

        <form action="OTPServlet" method="post">
            <label>Código OTP:</label>
            <input type="text" name="otp" required>

            <button type="submit" class="btn-primary">Verificar</button>
        </form>

        <p>Revise su correo.</p>

    </div> 
</div> 

</body>
</html>