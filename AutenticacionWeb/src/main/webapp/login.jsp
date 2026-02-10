<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Inicio de sesión</title>
<link rel="stylesheet" href="css/estilos.css">
</head>

<body>

<div class="login-container">

    <!--login normal -->
    <div class="login-card">
        <h2>Inicio de Sesión</h2>

        <% if (request.getAttribute("error") != null) { %>
            <p class="error-msg"><%= request.getAttribute("error") %></p>
        <% } %>

        <form action="LoginServlet" method="post">
            <label>DNI:</label>
            <input type="text" name="dni"
                   value="<%= request.getAttribute("dniRecordado") != null ? request.getAttribute("dniRecordado") : "" %>"
                   required>

            <label>Contraseña:</label>
            <input type="password" name="contrasena" required>

            <p><a href="recuperarContrasena.jsp">¿Olvidaste tu contraseña?</a></p>
            <button type="submit" class="btn-primary">Iniciar sesión</button>

            <input type="hidden" id="latitud" name="latitud">
            <input type="hidden" id="longitud" name="longitud">
        </form>
    </div>

    <!--login totp-->
    <div class="login-card">
        <h3>Iniciar sesión con Authenticator (TOTP)</h3>
        <form action="LoginTOTPServlet" method="post">
            <label>DNI:</label>
            <input type="text" name="dni" required>

            <label>Código TOTP:</label>
            <input type="text" name="totp" required>

            <button type="submit" class="btn-primary">Iniciar sesión con Authenticator</button>
        </form>
    </div>

    <!--login biometria-->
    <div class="login-card">
        <h3>Iniciar sesión con biometría</h3>
        <label>DNI:</label>
        <input type="text" id="dniBiometria" required>
        <button type="button" id="btnBiometria" class="btn-primary">Iniciar sesión con biometría</button>
    </div>

    <!--login fido2-->
    <div class="login-card">
        <h3>Iniciar sesión con dispositivo FIDO2</h3>
        <label>DNI:</label>
        <input type="text" id="dniFIDO2" required>
        <button type="button" id="btnFIDO2" class="btn-primary">Iniciar sesión con FIDO2</button>
    </div>
    
    <!--login passkey-->
	<div class="login-card">
	    <h3>Iniciar sesión con Passkey</h3>
	
	    <label>DNI:</label>
	    <input type="text" id="dniPasskey" required>
	
	    <button type="button" id="btnPasskey" class="btn-primary">
	        Iniciar sesión con Passkey
	    </button>
	</div>

    <p class="register-text">¿No tienes cuenta?  
        <a href="registro.jsp">Regístrate aquí</a>
    </p>

</div>



<script>

//obtener ubicacion
window.addEventListener("load", () => {
 if (!navigator.geolocation) {
     console.warn("Geolocalización no soportada en este navegador");
     return;
 }

 navigator.geolocation.getCurrentPosition(
     pos => {
         document.getElementById("latitud").value = pos.coords.latitude;
         document.getElementById("longitud").value = pos.coords.longitude;
         console.log("Ubicación obtenida:", pos.coords.latitude, pos.coords.longitude);
     },
     err => {
         console.warn("No se pudo obtener la ubicación:", err.message);
     },
     {
         enableHighAccuracy: true,
         timeout: 10000,   //10 segundos para responder
         maximumAge: 0
     }
 );
});

//funcoin base64url
function base64UrlToBase64(b64url) {
    b64url = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64url.length % 4 !== 0) b64url += '=';
    return b64url;
}

//biometria
document.getElementById('btnBiometria').addEventListener('click', async () => {
    try {
        const dni = document.getElementById('dniBiometria').value;
        if (!dni.trim()) { alert("Debes introducir un DNI."); return; }

        const response = await fetch('<%= request.getContextPath() %>/OpcionesAutServlet?dni=' + encodeURIComponent(dni));
        if (!response.ok) { alert("Error al obtener opciones de autenticación."); return; }

        const options = await response.json();
        options.challenge = Uint8Array.from(atob(base64UrlToBase64(options.challenge)), c => c.charCodeAt(0));

        if (options.allowCredentials) {
            options.allowCredentials = options.allowCredentials.map(cred => ({
                ...cred,
                id: Uint8Array.from(atob(base64UrlToBase64(cred.id)), c => c.charCodeAt(0))
            }));
        }

        const credential = await navigator.credentials.get({ publicKey: options });

        const body = {
            id: credential.id,
            rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
            type: credential.type,
            response: {
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature))),
                userHandle: credential.response.userHandle ? 
                            btoa(String.fromCharCode(...new Uint8Array(credential.response.userHandle))) : null
            }
        };

        const verifyResp = await fetch('<%= request.getContextPath() %>/AutServlet', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        const result = await verifyResp.json();
        if(result.success){ alert("Autenticación biométrica correcta."); window.location.href="verificaOTP.jsp"; }
        else { alert("Error en la biometría: " + result.message); }

    } catch(err) { console.error(err); alert("No se pudo iniciar la biometría: " + err); }
});


//fido2

document.getElementById('btnFIDO2').addEventListener('click', async () => {
    try {
        const dni = document.getElementById('dniFIDO2').value;
        if (!dni.trim()) { alert("Debes introducir un DNI."); return; }

        const response = await fetch('<%= request.getContextPath() %>/OpcionesFido2Servlet?dni=' + encodeURIComponent(dni));
        if (!response.ok) { alert("Error al obtener opciones de autenticación FIDO2."); return; }

        const options = await response.json();
        options.challenge = Uint8Array.from(atob(base64UrlToBase64(options.challenge)), c => c.charCodeAt(0));

        if (options.allowCredentials) {
            options.allowCredentials = options.allowCredentials.map(cred => ({
                ...cred,
                id: Uint8Array.from(atob(base64UrlToBase64(cred.id)), c => c.charCodeAt(0))
            }));
        }

        const credential = await navigator.credentials.get({ publicKey: options });

        const body = {
            id: credential.id,
            rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
            type: credential.type,
            response: {
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature))),
                userHandle: credential.response.userHandle ? 
                            btoa(String.fromCharCode(...new Uint8Array(credential.response.userHandle))) : null
            },
            dni: dni
        };

        const verifyResp = await fetch('<%= request.getContextPath() %>/AutFido2Servlet', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        const result = await verifyResp.json();
        if(result.success){ alert("Autenticación FIDO2 correcta."); window.location.href="verificaOTP.jsp"; }
        else { alert("Error en FIDO2: " + result.message); }

    } catch(err) { console.error(err); alert("No se pudo iniciar la autenticación FIDO2: " + err); }
});


//passkey
document.getElementById('btnPasskey').addEventListener('click', async () => {
 try {
     const dni = document.getElementById('dniPasskey').value;
     if (!dni.trim()) { alert("Debes introducir un DNI."); return; }

     const response = await fetch('<%= request.getContextPath() %>/OpcionesPasskeyServlet?dni=' + encodeURIComponent(dni));
     if (!response.ok) { alert("Error al obtener opciones de autenticación Passkey."); return; }

     const options = await response.json();
     options.challenge = Uint8Array.from(atob(base64UrlToBase64(options.challenge)), c => c.charCodeAt(0));

     if (options.allowCredentials) {
         options.allowCredentials = options.allowCredentials.map(cred => ({
             ...cred,
             id: Uint8Array.from(atob(base64UrlToBase64(cred.id)), c => c.charCodeAt(0))
         }));
     }

     const credential = await navigator.credentials.get({ publicKey: options });

     const body = {
         id: credential.id,
         rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
         type: credential.type,
         response: {
             clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
             authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
             signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature))),
             userHandle: credential.response.userHandle ? 
                         btoa(String.fromCharCode(...new Uint8Array(credential.response.userHandle))) : null
         },
         dni: dni
     };

     const verifyResp = await fetch('<%= request.getContextPath() %>/AutPasskeyServlet', {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify(body)
     });

     const result = await verifyResp.json();
     if(result.success){ alert("Autenticación Passkey correcta."); window.location.href="verificaOTP.jsp"; }
     else { alert("Error en Passkey: " + result.message); }

 } catch(err) { console.error(err); alert("No se pudo iniciar la autenticación Passkey: " + err); }
});

</script>

</body>
</html>
