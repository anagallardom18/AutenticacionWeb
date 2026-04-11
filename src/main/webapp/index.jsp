<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Inicio - Sistema de Autenticación</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/estilos.css?v=2">
</head>

<body>

<div class="login-container">

    <div class="login-card">
       
        <h2>Sistema de Autenticación</h2>

        <p class="text-center text-muted">
            Seleccione el método de acceso al sistema
        </p>

        <div class="index-actions">
            
            <a href="login1fa.jsp" class="no-decoration">
                <button class="btn-primary">
                    Login sencillo (1FA)
                </button>
            </a>

            <a href="login.jsp" class="no-decoration">
                <button class="btn-primary">
                    Login de Doble Factor (2FA)
                </button>
            </a>

            <div class="separator-text">O BIEN</div>

            <a href="QRMovilServlet" class="no-decoration">
                <button class="btn-secondary">
                    Acceder mediante Código QR (móvil)
                </button>
            </a>
            
        </div>
    </div>

</div>

</body>
</html>