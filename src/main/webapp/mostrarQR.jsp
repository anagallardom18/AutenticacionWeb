<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Acceso mediante QR</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="<%= request.getContextPath() %>/css/estilos.css?v=2">
</head>

<body>

<div class="login-container">

    <div class="login-card">

        <h2>Acceso mediante QR</h2>

        <p class="text-center text-muted">
            Escanee este código con su dispositivo móvil para validar su identidad.
        </p>

        <div class="qr-container">
            <img src="${qrImage}" class="qr-img" alt="Código QR de acceso"/>
        </div>

        <div class="margin-top-md">
            <a href="index.jsp" class="no-decoration">
                <button class="btn-primary">
                    Volver al inicio
                </button>
            </a>
        </div>

    </div>

</div>

</body>
</html>