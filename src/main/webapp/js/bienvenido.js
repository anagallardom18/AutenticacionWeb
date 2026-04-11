console.log("bienvenido.js cargado correctamente");

/**
 * UTILIDADES DE CONVERSIÓN
 */
function base64UrlToBytes(b64url) {
    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64.padEnd(b64.length + (4 - b64.length % 4) % 4, '='));
    return Uint8Array.from(bin, c => c.charCodeAt(0));
}

function bufferToB64Url(buffer) {
    const bin = String.fromCharCode(...new Uint8Array(buffer));
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * MANEJADOR DE ERRORES DE WEBAUTHN
 */
function manejarErrorWebAuthn(err, contexto) {
    console.error(`Error en ${contexto}:`, err);

    // Si el usuario cancela la operación o cierra el cuadro de diálogo
    if (err.name === 'NotAllowedError' || err.name === 'AbortError') {
        console.warn("Operación cancelada por el usuario.");
        return; 
    }

    // Si la operación tarda demasiado
    if (err.name === 'SecurityError' || err.name === 'TimeoutError') {
        alert("La operación ha caducado. Inténtelo de nuevo.");
        return;
    }

    // Otros errores técnicos
    alert("No se pudo completar el registro: " + err.message);
}

/**
 * 1. REGISTRO BIOMÉTRICO
 */
async function registrarBiometria(dni) {
    console.log("Iniciando registro biométrico...");
    try {
        const response = await fetch(`${contextPath}/RegistroBiometriaServlet?dni=${dni}`);
        if (!response.ok) throw new Error("Error al obtener opciones.");

        const options = await response.json();
        options.challenge = base64UrlToBytes(options.challenge);
        options.user.id = base64UrlToBytes(options.user.id);

        const credential = await navigator.credentials.create({ publicKey: options });

        const body = {
            id: credential.id,
            rawId: bufferToB64Url(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: bufferToB64Url(credential.response.attestationObject),
                clientDataJSON: bufferToB64Url(credential.response.clientDataJSON)
            },
            dni: dni
        };

        const guardar = await fetch(`${contextPath}/GuardaBiometriaServlet`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (guardar.ok) alert("Biometría registrada correctamente.");
        else alert("Error al guardar en el servidor.");
    } catch (err) {
        manejarErrorWebAuthn(err, "Biometría");
    }
}

/**
 * 2. REGISTRO FIDO2
 */
async function registrarFIDO2(dni) {
    console.log("Iniciando registro FIDO2...");
    try {
        const resp = await fetch(`${contextPath}/OpcionesFido2Servlet?dni=${encodeURIComponent(dni)}`);
        if (!resp.ok) throw new Error("Error al obtener opciones.");

        const options = await resp.json();
        options.challenge = base64UrlToBytes(options.challenge);
        options.user.id = base64UrlToBytes(options.user.id);

        const credential = await navigator.credentials.create({ publicKey: options });

        const body = {
            id: credential.id,
            rawId: bufferToB64Url(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: bufferToB64Url(credential.response.attestationObject),
                clientDataJSON: bufferToB64Url(credential.response.clientDataJSON)
            },
            dni: dni
        };

        const guardarResp = await fetch(`${contextPath}/GuardaFido2Servlet`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (guardarResp.ok) alert("Dispositivo FIDO2 registrado correctamente.");
        else alert("Error al guardar FIDO2.");
    } catch (err) {
        manejarErrorWebAuthn(err, "FIDO2");
    }
}

/**
 * 3. REGISTRO PASSKEY
 */
async function registrarPasskey(dni) {
    console.log("Iniciando registro de Passkey...");
    try {
        const res = await fetch(`${contextPath}/OpcionesPasskeyServlet?dni=${encodeURIComponent(dni)}`);
        if (!res.ok) throw new Error("Servidor no responde.");

        const options = await res.json();
        options.challenge = base64UrlToBytes(options.challenge);
        options.user.id = base64UrlToBytes(options.user.id);

        const credential = await navigator.credentials.create({ publicKey: options });

        const body = {
            id: credential.id,
            rawId: bufferToB64Url(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: bufferToB64Url(credential.response.attestationObject),
                clientDataJSON: bufferToB64Url(credential.response.clientDataJSON)
            },
            dni: dni
        };

        const guardarResp = await fetch(`${contextPath}/GuardaPasskeyServlet`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (guardarResp.ok) alert("Passkey registrada correctamente.");
        else alert("Error al guardar Passkey.");
    } catch (err) {
        manejarErrorWebAuthn(err, "Passkey");
    }
}