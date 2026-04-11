/* global contextPath */

// --- 1. UBICACIÓN  ---
window.addEventListener("load", () => {
    if (!navigator.geolocation) return;
    navigator.geolocation.getCurrentPosition(
        pos => {
            const lat = document.getElementById("latitud");
            const lon = document.getElementById("longitud");
            if(lat) lat.value = pos.coords.latitude;
            if(lon) lon.value = pos.coords.longitude;
        },
        err => console.warn("Error ubicación:", err.message),
        { enableHighAccuracy: true, timeout: 10000 }
    );
});

// --- 2. UTILIDAD BASE64 ---
function base64UrlToBase64(b64url) {
    let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) b64 += '=';
    return b64;
}

// --- 3. BIOMETRÍA (1FA) ---
document.getElementById('btnBiometria').addEventListener('click', async (e) => {
    if (e.currentTarget.hasAttribute('disabled')) return;
    try {
        const dni = document.getElementById('dniBiometria').value;
        if (!dni.trim()) return alert("Debes introducir un DNI.");

        const response = await fetch(`${contextPath}/OpcionesBiometriaServlet?dni=${encodeURIComponent(dni)}`);
        const options = await response.json();

        options.challenge = Uint8Array.from(atob(base64UrlToBase64(options.challenge)), c => c.charCodeAt(0));
        if (options.allowCredentials) {
            options.allowCredentials = options.allowCredentials.map(cred => ({
                ...cred, id: Uint8Array.from(atob(base64UrlToBase64(cred.id)), c => c.charCodeAt(0))
            }));
        }
        
        const credential = await navigator.credentials.get({ publicKey: options });

        const body = {
            modoLogin: "1FA",   
            dni: dni,
            rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
            response: {
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature)))
            }
        };

        const verifyResp = await fetch(`${contextPath}/AutBiometriaServlet`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        const result = await verifyResp.json();
        if(result.success){
            alert(result.message || "Autenticación correcta.");
            window.location.href = result.redirect || "bienvenido.jsp";
        } else {
            alert("Error: " + result.message);
        }
    } catch(err) {
        alert("Error biometría: " + err.message);
    }
});

// --- 4. FIDO2 (1FA) ---
document.getElementById('btnFIDO2').addEventListener('click', async (e) => {
    if (e.currentTarget.hasAttribute('disabled')) return; 
    try {
        const dni = document.getElementById('dniFIDO2').value;
        if (!dni.trim()) return alert("Debes introducir un DNI.");

        const response = await fetch(`${contextPath}/OpcionesFido2Servlet?dni=${encodeURIComponent(dni)}`);
        const options = await response.json();

        options.challenge = Uint8Array.from(atob(base64UrlToBase64(options.challenge)), c => c.charCodeAt(0));
        if (options.allowCredentials) {
            options.allowCredentials = options.allowCredentials.map(cred => ({
                ...cred, id: Uint8Array.from(atob(base64UrlToBase64(cred.id)), c => c.charCodeAt(0))
            }));
        }
        
        const credential = await navigator.credentials.get({ publicKey: options });

        const body = {
            modoLogin: "1FA",  
            dni: dni,
            rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
            response: {
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature)))
            }
        };

        const verifyResp = await fetch(`${contextPath}/AutFido2Servlet`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        const result = await verifyResp.json();
        if(result.success){
            alert(result.message || "Autenticación correcta.");
            window.location.href = result.redirect || "bienvenido.jsp";
        } else {
            alert("Error: " + result.message);
        }
    } catch(err) {
        alert("Error FIDO2: " + err.message);
    }
});

// --- 5. PASSKEY (1FA) ---
document.getElementById('btnPasskey').addEventListener('click', async (e) => {
    if (e.currentTarget.hasAttribute('disabled')) return;
    try {
        const dni = document.getElementById('dniPasskey').value;
        if (!dni.trim()) return alert("Debes introducir un DNI.");

        const response = await fetch(`${contextPath}/OpcionesPasskeyServlet?dni=${encodeURIComponent(dni)}`);
        const options = await response.json();

        options.challenge = Uint8Array.from(atob(base64UrlToBase64(options.challenge)), c => c.charCodeAt(0));
        if (options.allowCredentials) {
            options.allowCredentials = options.allowCredentials.map(cred => ({
                ...cred, id: Uint8Array.from(atob(base64UrlToBase64(cred.id)), c => c.charCodeAt(0))
            }));
        }
        
        const credential = await navigator.credentials.get({ publicKey: options });

        const body = {
            modoLogin: "1FA",  
            dni: dni,
            rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
            response: {
                clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
                authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
                signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature)))
            }
        };

        const verifyResp = await fetch(`${contextPath}/AutPasskeyServlet`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        const result = await verifyResp.json();
        if(result.success){
            alert(result.message || "Autenticación correcta.");
            window.location.href = result.redirect || "bienvenido.jsp";
        } else {
            alert("Error: " + result.message);
        }
    } catch(err) {
        alert("Error Passkey: " + err.message);
    }
});