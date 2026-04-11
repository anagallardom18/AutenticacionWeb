# AutenticacionWeb: Sistema de Autenticación Multifactor Adaptativo

Este proyecto implementa una infraestructura de inicio de sesión multifactor (MFA) robusta, diseñada para mitigar ataques de identidad mediante la combinación de factores de conocimiento, posesión e inherencia, junto con un motor de decisiones basado en riesgo.

---

## Funcionalidades de Seguridad

La aplicación implementa un flujo de autenticación inteligente y flexible:

* **MFA Multifactor:** Soporte para múltiples factores:
    * **Conocimiento:** Contraseñas tradicionales con hashing seguro.
    * **Posesión:** TOTP (Google Authenticator), códigos OTP por correo y llaves físicas (FIDO2).
    * **Inherencia:** Biometría y Passkeys (WebAuthn).

* **Autenticación Adaptativa basada en Riesgo (RBA):**
    * El sistema analiza la IP de conexión y la geolocalización GPS (mediante la fórmula de Haversine).
    * Si se detecta un acceso desde una ubicación inusual (distancia superior a 50 km de la habitual) o una IP desconocida, el sistema eleva automáticamente el nivel de seguridad.
    * Esta elevación exige un factor adicional incluso si el usuario ha seleccionado el modo simplificado (1FA), mitigando el riesgo de suplantación de identidad.

* **Control de Fuerza Bruta:** Bloqueo automático del factor de contraseña tras 3 intentos fallidos.

* **Gestión de Sesión:** Registro de los factores utilizados durante la sesión para permitir una navegación fluida y segura.

* **Acceso Multidispositivo:** Generación de códigos QR vinculados a túneles seguros para integración con dispositivos móviles.

---

## Tecnologías y Librerías

* **Backend:** Java 21, Jakarta EE (Servlets 6.0).
* **Gestión de Proyecto:** Maven.
* **Seguridad y Protocolos:** FIDO2 / Passkeys (WebAuthn API), Jakarta Mail.
* **Componentes Adicionales:**
    * **ZXing:** Generación de códigos QR.
    * **Gson / JSON:** Procesamiento de datos.
    * **MySQL:** Persistencia de datos.
* **Infraestructura:** Apache Tomcat 10.1+, ngrok.

---

## Base de Datos

La aplicación utiliza un esquema relacional denominado `autenticacion_db`.
El script de inicialización con la estructura de tablas y configuraciones iniciales se encuentra en:
`src/database/schema.sql`

---

## Instalación y Despliegue

### 1. Clonación e Importación
Descargue el repositorio e impórtelo en su entorno de desarrollo (Eclipse o IntelliJ) como un proyecto Maven existente.

### 2. Configuración de la Base de Datos
1. Ejecute el script `schema.sql` en su instancia de MySQL.
2. Configure el recurso JDBC en Tomcat apuntando a `jdbc/autenticacion`.

### 3. Configuración del Servicio de Correo y Seguridad (MFA) 
Para el envío de códigos OTP, el sistema utiliza el protocolo SMTP con un sistema de cifrado avanzado **AES-256 (GCM)**. 
Esto garantiza que las credenciales de correo nunca se almacenen en texto plano en la base de datos.

#### A. Obtención de la credencial de Google 
Debido a las políticas de seguridad de Google, no se puede utilizar la contraseña principal. 
1. Asegúrese de tener activada la **Verificación en dos pasos** en su cuenta de Google. 
2. Acceda al panel de [Contraseñas de aplicación](https://myaccount.google.com/apppasswords). 
3. Cree una nueva aplicación (ej: ProyectoAutenticacion) y **copie el código de 16 caracteres** generado. 

#### B. Configuración de la Llave Maestra (Variable de Entorno)
Por motivos de seguridad, la clave de cifrado no está escrita en el código fuente. 
Debe configurarse de forma externa: 
1. Defina una variable de entorno en su sistema o IDE (Eclipse/Tomcat) llamada: AES_KEY_APP 
2. El valor debe ser una cadena alfanumérica de **exactamente 32 caracteres** (esta será la llave que cifra y descifra todo el sistema).

#### C. Cifrado de credenciales y actualización de BD 
Antes de guardar la contraseña de Google en la base de datos, debe cifrarla usando el módulo de seguridad del proyecto: 
1. Configure la variable AES_KEY_APP en las *Run Configurations* de la clase GeneradorPassword.java. 
2. Ejecute dicha clase e introduzca su contraseña de 16 caracteres de Google cuando se le solicite (o configúrela en el código del Main). 
3. El programa devolverá un **Token cifrado** (ej: 7jHk2...). Copie este valor. 
4. Actualice la base de datos con el siguiente script SQL:

```sql
-- Configuración de correo
INSERT INTO settings (clave, valor) VALUES
('email_user', 'TU_CORREO'),
('email_password', 'TU_CLAVE_CIFRADA'),
('smtp_host', 'smtp.gmail.com'),
('smtp_port', '587'),
('URL_PUBLICA', 'TU_URL_NGROK');
```
### 4. Ejecución en servidor

1. Configura un servidor Apache Tomcat en Eclipse.
2. Despliega el proyecto en el servidor.
3. Inicia el servidor.

La aplicación estará disponible en:

```text
http://localhost:8080/AutenticacionWeb/
```

### 5. Exponer el servidor con ngrok (solo acceso externo)

Este paso solo es necesario si se desea acceder a la aplicación desde un dispositivo externo (por ejemplo, al escanear un QR desde el móvil).

#### Pasos:

1. Iniciar ngrok en el puerto 8080:

```bash
ngrok http 8080
```
2. Copiar la URL pública generada (por ejemplo: https://tu-url-de-ngrok.ngrok-free.app).

3. Configurar esa URL en la base de datos dentro del campo URL_PUBLICA en el script src/database/schema.sql:

```sql
INSERT INTO settings (clave, valor) VALUES
('email_user', 'TU_CORREO'),
('email_password', 'TU_CLAVE_CIFRADA'),
('smtp_host', 'smtp.gmail.com'),
('smtp_port', '587'),
('URL_PUBLICA', 'TU_URL_NGROK');
```