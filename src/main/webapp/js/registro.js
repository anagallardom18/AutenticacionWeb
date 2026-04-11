/**
 * Validación de formulario de registro
 */
document.addEventListener("DOMContentLoaded", () => {
    const registroForm = document.getElementById("registroForm");

    if (registroForm) {
        registroForm.addEventListener("submit", function(e) {
            const pass1 = document.getElementById("contrasena").value;
            const pass2 = document.getElementById("contrasena2").value;

            if (pass1 !== pass2) {
                e.preventDefault(); // Evita enviar el formulario al servidor
                alert("Las contraseñas no coinciden.");
                document.getElementById("contrasena2").focus();
            }
        });
    }
});