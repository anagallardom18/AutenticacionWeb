/**
 * Lógica de Autenticación Multimodal (Biometría, FIDO2, Passkey)
 * Manejo de errores y geolocalización adaptativa.
 */

/* global contextPath */

// --- 1. GEOLOCALIZACIÓN ADAPTATIVA ---
window.addEventListener("load", () => {
    if (!navigator.geolocation) return;

    navigator.geolocation.getCurrentPosition(
        pos => {
            const latInput = document.getElementById("latitud");
            const lonInput = document.getElementById("longitud");
            if(latInput) latInput.value = pos.coords.latitude;
            if(lonInput) lonInput.value = pos.coords.longitude;
        },
        err => console.warn("Error ubicación:", err.message),
        { enableHighAccuracy: true, timeout: 10000 }
    );
});

// --- 2. UTILIDADES DE CONVERSIÓN ---
function base64UrlToBase64(b64url) {
    let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) b64 += '=';
    return b64;
}

/**
 * 3. MANEJADOR DE ERRORES WEBAUTHN
 */
function manejarErrorWebAuthn(err, factorNombre) {
    // Si el usuario cancela (clic fuera o botón cancelar), silenciamos el error
    if (err.name === 'NotAllowedError' || err.name === 'AbortError') {
        console.warn(`${factorNombre}: Operación cancelada por el usuario.`);
        return; // Salimos sin mostrar alertas
    }
    
    // Si la operación caduca por falta de respuesta del usuario
    if (err.name === 'TimeoutError') {
        alert(`${factorNombre}: El tiempo de espera ha caducado.`);
        return;
    }

    // Para cualquier otro error real, mostramos aviso
    console.error(`Error en ${factorNombre}:`, err);
    alert(`No se pudo completar la verificación con ${factorNombre}.`);
}

/**
 * 4. MANEJADOR DE RESPUESTAS DEL SERVIDOR
 * Procesa la respuesta de los servlets de autenticación.
 */
async function manejarRespuestaServidor(response) {
    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || "Error en la comunicación con el servidor.");
    }

    const result = await response.json();

    if (result.success) {
        // Notificación según el estado de la 'mochila' de factores
        if (result.redirect && result.redirect.includes("verificaOTP")) {
            alert("Factor verificado. Por seguridad, introduzca el código enviado a su correo.");
        } 
        else if (result.requireMoreFactors) {
            alert(result.message || "Paso completado. Se requiere un factor de una categoría distinta.");
        }
        else {
            alert("Identidad verificada con éxito.");
        }
        // Redirección final
        window.location.href = result.redirect || "bienvenido.jsp";
    } else {
        alert("Fallo en la validación: " + (result.message || "Credencial no válida."));
    }
}

/**
 * 5. LÓGICA DE EJECUCIÓN WEBAUTHN
 * Orquestación de la comunicación entre el Hardware y el Servidor.
 */
async function ejecutarAutenticacionWebAuthn(dni, endpoint, factorNombre) {
    // A. Obtener opciones del servidor (Desafío)
    const respOp = await fetch(`${contextPath}/${endpoint}?dni=${encodeURIComponent(dni)}`);
    if (!respOp.ok) throw new Error(`No se pudo conectar con ${endpoint}`);
    const options = await respOp.json();

    // B. Preparar datos para el navegador
    options.challenge = Uint8Array.from(atob(base64UrlToBase64(options.challenge)), c => c.charCodeAt(0));
    if (options.allowCredentials) {
        options.allowCredentials = options.allowCredentials.map(c => ({
            ...c, id: Uint8Array.from(atob(base64UrlToBase64(c.id)), b => b.charCodeAt(0))
        }));
    }

    // C. Lanzar petición al hardware 
    const credential = await navigator.credentials.get({ publicKey: options });

    // D. Empaquetar respuesta para el servidor
    const body = {
        modoLogin: "2FA",
        dni: dni,
        rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
        response: {
            clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
            authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
            signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature)))
        }
    };

    // E. Enviar al servlet verificador (AutBiometriaServlet, AutFido2Servlet, etc.)
    const authEndpoint = endpoint.replace("Opciones", "Aut"); 
    const verifyResp = await fetch(`${contextPath}/${authEndpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });

    await manejarRespuestaServidor(verifyResp);
}

// --- 6. ASIGNACIÓN DE EVENTOS A LOS BOTONES ---

// Botón de Biometría
const btnBiometria = document.getElementById('btnBiometria');
if (btnBiometria) {
    btnBiometria.addEventListener('click', async (e) => {
        try {
            const dni = document.getElementById('dniBiometria').value;
            if (!dni) return alert("Por favor, introduzca su DNI.");
            await ejecutarAutenticacionWebAuthn(dni, 'OpcionesBiometriaServlet', 'Biometría');
        } catch(err) {
            manejarErrorWebAuthn(err, 'Biometría');
        }
    });
}

// Botón de Llave FIDO2
const btnFIDO2 = document.getElementById('btnFIDO2');
if (btnFIDO2) {
    btnFIDO2.addEventListener('click', async (e) => {
        try {
            const dni = document.getElementById('dniFIDO2').value;
            if (!dni) return alert("Por favor, introduzca su DNI.");
            await ejecutarAutenticacionWebAuthn(dni, 'OpcionesFido2Servlet', 'FIDO2');
        } catch(err) {
            manejarErrorWebAuthn(err, 'FIDO2');
        }
    });
}

// Botón de Passkey
const btnPasskey = document.getElementById('btnPasskey');
if (btnPasskey) {
    btnPasskey.addEventListener('click', async (e) => {
        try {
            const dni = document.getElementById('dniPasskey').value;
            if (!dni) return alert("Por favor, introduzca su DNI.");
            await ejecutarAutenticacionWebAuthn(dni, 'OpcionesPasskeyServlet', 'Passkey');
        } catch(err) {
            manejarErrorWebAuthn(err, 'Passkey');
        }
    });
}