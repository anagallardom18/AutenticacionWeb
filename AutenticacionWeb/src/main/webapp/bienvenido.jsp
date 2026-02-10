<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ page import="jakarta.servlet.http.HttpSession" %>
<%
    String usuario = (session != null) ? (String) session.getAttribute("usuario") : null;
    if (usuario == null) {
        response.sendRedirect("login.jsp");
        return;
    }
%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Bienvenido</title>
<link rel="stylesheet" href="<%= request.getContextPath() %>/css/estilos.css">
</head>
<body>

<div class="login-container">
    <div class="login-card">
        <h2>Bienvenido <%= usuario %></h2>

        <hr>

        <h3>Seguridad de la cuenta</h3>

        <!-- Botón para configurar TOTP -->
        <form action="ConfigurarTOTPServlet" method="get">
            <button type="submit" class="btn-primary">Configurar Authenticator (TOTP)</button>
        </form>

        <br>

        <!-- Botón para registrar dispositivo biométrico -->
        <button type="button" class="btn-primary" onclick="registrarCredencial('<%= usuario %>')">
            Registrar dispositivo biométrico
        </button>

        <br><br>

        <!-- Botón para registrar dispositivo FIDO2 físico -->
        <button type="button" class="btn-primary" onclick="registrarFIDO2('<%= usuario %>')">
            Registrar dispositivo FIDO2 (USB/NFC)
        </button>
        
		<!-- Botón para registrar Passkey -->
		<br><br>
		<button type="button" class="btn-primary" onclick="registrarPasskey('<%= usuario %>')">
		    Registrar Passkey
		</button>
        <hr>

        <!-- Botón de cerrar sesión -->
        <form action="LogoutServlet" method="get">
            <button type="submit" class="btn-secondary">Cerrar sesión</button>
        </form>
    </div>
</div>

<script>

//funcion Base64URL

function base64UrlToBase64(b64url) {
    b64url = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64url.length % 4 !== 0) b64url += '=';
    return b64url;
}

function arrayBufferToBase64Url(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    bytes.forEach((b) => binary += String.fromCharCode(b));
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

//registrar credencial biométrica 
async function registrarCredencial(dni) {
    if (!dni) { alert("Usuario no válido."); return; }

    const response = await fetch('<%= request.getContextPath() %>/RegistroBiometriaServlet?dni=' + encodeURIComponent(dni));
    if (!response.ok) { alert("Error al obtener opciones de registro biométrico."); return; }

    const options = await response.json();
    options.challenge = Uint8Array.from(atob(base64UrlToBase64(options.challenge)), c => c.charCodeAt(0));
    options.user.id = Uint8Array.from(atob(base64UrlToBase64(options.user.id)), c => c.charCodeAt(0));

    const credential = await navigator.credentials.create({ publicKey: options });

    const body = {
        id: credential.id,
        rawId: arrayBufferToBase64Url(credential.rawId),
        type: credential.type,
        response: {
            attestationObject: arrayBufferToBase64Url(credential.response.attestationObject),
            clientDataJSON: arrayBufferToBase64Url(credential.response.clientDataJSON)
        },
        dni: dni
    };

    const guardarResp = await fetch('<%= request.getContextPath() %>/GuardaCredencialServlet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });

    if (guardarResp.ok) alert("Credencial biométrica registrada correctamente.");
    else alert("Error al guardar la credencial biométrica.");
}


//registrar dispositivo FIDO2 físico
async function registrarFIDO2(dni) {
    if (!dni) { alert("Usuario no válido."); return; }

    const resp = await fetch('<%= request.getContextPath() %>/RegistroFido2Servlet?dni=' + encodeURIComponent(dni));
    if (!resp.ok) { alert("Error al obtener opciones FIDO2."); return; }

    const options = await resp.json();
    options.challenge = Uint8Array.from(atob(base64UrlToBase64(options.challenge)), c => c.charCodeAt(0));
    options.user.id = Uint8Array.from(atob(base64UrlToBase64(options.user.id)), c => c.charCodeAt(0));

    if (options.excludeCredentials) {
        options.excludeCredentials = options.excludeCredentials.map(c => ({
            ...c,
            id: Uint8Array.from(atob(base64UrlToBase64(c.id)), ch => ch.charCodeAt(0))
        }));
    }

    const credential = await navigator.credentials.create({ publicKey: options });

    const body = {
        id: credential.id,
        rawId: arrayBufferToBase64Url(credential.rawId),
        type: credential.type,
        response: {
            attestationObject: arrayBufferToBase64Url(credential.response.attestationObject),
            clientDataJSON: arrayBufferToBase64Url(credential.response.clientDataJSON)
        },
        dni: dni
    };

    const guardarResp = await fetch('<%= request.getContextPath() %>/GuardaFido2Servlet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });

    if (guardarResp.ok) alert("Dispositivo FIDO2 registrado correctamente.");
    else alert("Error al guardar el dispositivo FIDO2.");
}


//registrar Passkey
async function registrarPasskey(dni) {
 if (!dni) { alert("Usuario no válido."); return; }

 try {
 
     const res = await fetch('<%= request.getContextPath() %>/RegistroPasskeyServlet?dni=' + encodeURIComponent(dni));
     if (!res.ok) { 
         const msg = await res.text();
         throw new Error("Error al obtener opciones Passkey: " + msg);
     }

     const options = await res.json();

     //convertir challenge y user.id a Uint8Array
     options.challenge = Uint8Array.from(atob(base64UrlToBase64(options.challenge)), c => c.charCodeAt(0));
     options.user.id = Uint8Array.from(atob(base64UrlToBase64(options.user.id)), c => c.charCodeAt(0));

     //crear la credencial con WebAuthn
     const credential = await navigator.credentials.create({ publicKey: options });

     //preparar datos para enviar al servlet que guarda la passkey
     const body = {
         id: credential.id,
         rawId: arrayBufferToBase64Url(credential.rawId),
         type: credential.type,
         response: {
             attestationObject: arrayBufferToBase64Url(credential.response.attestationObject),
             clientDataJSON: arrayBufferToBase64Url(credential.response.clientDataJSON)
         },
         dni: dni
     };

     //enviar al servlet de guardado
     const guardarResp = await fetch('<%= request.getContextPath() %>/GuardaPasskeyServlet', {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify(body)
     });

     if (guardarResp.ok) alert("Passkey registrada correctamente.");
     else alert("Error al guardar la Passkey.");

 } catch (err) {
     console.error(err);
     alert("Error al registrar Passkey: " + err.message);
 }
}

</script>

</body>
</html>
