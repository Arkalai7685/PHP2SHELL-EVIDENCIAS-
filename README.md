Informe Técnico: Análisis, Explotación y Mitigación de PHP2Shell (TryHackMe)

Alumno: Álvaro Manuel Castillo Arancibia

Carrera: Ingeniería en Ciberseguridad


1. Objetivo y Resumen Ejecutivo

El presente informe técnico documenta el análisis de vulnerabilidades, el proceso de validación en un entorno controlado y las propuestas de remediación para la cadena de explotación conocida como PHP2Shell (CVE-2026-109618 y CVE-2026-109619).

A diferencia de las vulnerabilidades web tradicionales que se originan por errores de codificación en la lógica de la aplicación (como validaciones deficientes o inyecciones SQL), PHP2Shell reside directamente en el motor de ejecución (runtime) de PHP (presente desde la versión 5.4.0 hasta versiones anteriores a los parches de octubre de 2026). Esta falla permite que un atacante remoto no autenticado provoque una corrupción de memoria durante el procesamiento de peticiones HTTP multipart/form-data, logrando evadir la protección ASLR (Address Space Layout Randomisation) y ejecutar código arbitrario (RCE) incluso contra servidores que alojan un script PHP de una sola línea sin formularios ni interacción con el usuario.

2. Análisis Técnico de las Vulnerabilidades

2.1. Superficie de Ataque: session.upload_progress

Por defecto, el motor de PHP mantiene habilitada la directiva session.upload_progress, diseñada para rastrear el estado de subida de archivos en tiempo real. Cuando un cliente envía una petición POST de tipo multipart/form-data que incluye el parámetro PHP_SESSION_UPLOAD_PROGRESS, PHP inicializa automáticamente el seguimiento de sesión.

Condición crítica: Este procesamiento ocurre en la etapa de body parsing del motor de PHP, antes de que se compile o ejecute el script PHP solicitado. Por lo tanto, no requiere que la aplicación web invoque session_start(), no necesita autenticación previa y tampoco exige que el archivo destino procese subidas de archivos.

2.2. Causa Raíz: Agotamiento de Memoria, bailout y Puntero Colgante (CWE-824)

Cuando una petición HTTP consume toda la memoria asignada al script (memory_limit), el motor de PHP no realiza un cierre convencional, sino que ejecuta una rutina de emergencia mediante un salto no local (longjmp) denominada internamente bailout, emitiendo el error fatal "Allowed memory size of X bytes exhausted".

Corrupción de Estado: Si el agotamiento de memoria se produce en la ventana exacta posterior a liberar un bloque de memoria del identificador de sesión, pero antes de anular el puntero que hace referencia a dicho bloque, el salto bailout interrumpe el flujo normal y omite la limpieza de la variable.

Puntero Colgante (Dangling Pointer): Como resultado, queda una referencia activa apuntando a memoria ya liberada (CWE-824: Access of Uninitialised Pointer).

Persistencia en el Servidor Web: En despliegues basados en Apache Prefork con mod_php, los procesos worker no se destruyen tras finalizar una petición, sino que se reutilizan para atender peticiones subsiguientes. El puntero colgante sobrevive en la memoria del worker y queda expuesto para ser manipulado en la siguiente conexión HTTP.

2.3. Cadena de Explotación: De Fuga de Memoria a Ejecución Remota

La intrusión se divide en tres etapas encadenadas:

Etapa 1 y 2 — Divulgación de Memoria y Evasión de ASLR (CVE-2026-109618): En la petición inmediatamente posterior al bailout, el atacante ocupa el bloque de memoria liberado y altera la estructura interna para inflar artificialmente la longitud del ID de sesión (PHPSESSID). Cuando el servidor responde con la cabecera HTTP Set-Cookie, concatena y envía al cliente hasta 67 KB de memoria interna del proceso. Mediante dos iteraciones, se extraen los punteros necesarios para calcular la dirección base del heap (chunk base) y la dirección base de la librería compartida de PHP (libphp base), neutralizando la protección ASLR.

Etapa 3 — Ejecución Remota de Código (CVE-2026-109619): Con las direcciones de memoria exactas resueltas en tiempo real, se reutiliza la referencia colgante para inyectar una estructura HashTable falsificada en el heap. El ataque sobrescribe su puntero destructor (pDestructor) para que apunte a la función interna system() (a través de zif_system). Cuando la petición finaliza y PHP ejecuta su rutina de recolección de basura para destruir la tabla hash, termina invocando system() con el comando suministrado por el atacante bajo los privilegios del usuario www-data.

3. Metodología y Evidencias del Laboratorio

Fase 1: Reconocimiento del Contenedor y Entorno

Se inició la auditoría verificando el estado de los contenedores Docker en ejecución dentro de la máquina del laboratorio para identificar el servicio objetivo:

docker ps --format '{{.Names}} {{.Image}} {{.Status}}'


A continuación, se consultó la versión exacta del intérprete PHP dentro del contenedor php2shell-target, confirmando que ejecuta PHP 8.4.26 (cli) sobre Zend Engine v4.4.26, una versión vulnerable previa al parche de seguridad:

docker exec php2shell-target php -v


Fase 2: Auditoría de la Aplicación Web Objetivo

Se realizó una petición HTTP local hacia el puerto 8088 y se inspeccionó el código fuente alojado en /var/www/html/index.php dentro del contenedor:

curl -s http://127.0.0.1:8088/index.php
docker exec php2shell-target cat /var/www/html/index.php


La revisión confirma que el archivo index.php contiene únicamente la instrucción <?php echo "OK\n"; ?>. Esto comprueba que la superficie de ataque no depende de errores de programación en la aplicación web, sino del comportamiento interno del motor de PHP.

Fase 3: Análisis de Herramientas y Prueba de Ejecución Remota (RCE)

Se inspeccionó el directorio ~/php2shell-bypass-aslr-exp, el cual contiene la prueba de concepto (exploit.py), la documentación técnica de investigación y los archivos de offsets:

ls ~/php2shell-bypass-aslr-exp


Se procedió a ejecutar el script de validación contra el endpoint http://127.0.0.1:8088/index.php utilizando la instrucción de prueba por defecto (id>/out/p1):

python3 exploit.py -u http://127.0.0.1:8088/index.php


El resultado en consola confirma la efectividad de las tres fases de la cadena de ataque:

Stage 1 (Heap Leak): Filtración exitosa con chunk base = 0x75847fe00000.

Stage 2 (libphp Leak): Filtración exitosa con libphp base = 0x7584819d8000.

Stage 3 (RCE): Cálculo de las direcciones HTDATA=0x75847fe690d8 y ZIF=0x758481e3d370, logrando la ejecución del comando id con salida uid=33(www-data) gid=33(www-data) groups=33(www-data).

Fase 4: Captura de la Evidencia Final (Flag)

Debido a la geometría del bloque de memoria sobrescrito en la estructura HashTable, el comando a inyectar tiene una restricción de longitud de 14 bytes. En el entorno de laboratorio, la bandera se ubica en la raíz bajo el nombre /f. Se ejecutó la prueba redirigiendo el contenido hacia el archivo de validación compartido:

python3 exploit.py -u http://127.0.0.1:8088/index.php -c 'cat /f>/out/p1' --proof-file out/p1


(Nota de seguridad: El contenido de la flag ha sido censurado en la evidencia gráfica para cumplir con las políticas de publicación en repositorios públicos).

4. Detección (Blue Team) y Propuesta de Remediaciones

4.1. Indicadores de Compromiso y Detección en Tráfico/Logs

Un equipo de respuesta a incidentes o monitoreo (SOC) puede detectar la explotación de PHP2Shell mediante tres indicadores clave:

Anomalías en la cabecera Set-Cookie: Un identificador PHPSESSID estándar mide entre 26 y 32 caracteres. Durante la fase de fuga de memoria (CVE-2026-109618), el servidor emite cabeceras Set-Cookie de aproximadamente 67 KB llenas de datos binarios de la memoria del proceso.

Registros de Errores de PHP (error.log): Incremento súbito y repetitivo de errores fatales con el mensaje "Allowed memory size of X bytes exhausted", generados cuando el atacante fuerza la condición de bailout.

Registros de Acceso HTTP (access.log): Ráfagas de peticiones POST multipart/form-data originadas desde una misma dirección IP hacia scripts que no gestionan formularios de carga (como index.php).

4.2. Medidas Correctivas y de Mitigación

Actualización del Motor PHP (Remediación Definitiva):
Aplicar de forma inmediata las actualizaciones oficiales lanzadas por The PHP Group que corrigen la corrupción de estado durante el aborto de memoria ("Avoid state corruption via bailout"):

Actualizar a PHP 8.5.12 o superior.

Actualizar a PHP 8.4.27 o superior.

Actualizar a PHP 8.3.36 o superior.

Actualizar a PHP 8.2.35 o superior.

Deshabilitación de Seguimiento de Subida en php.ini (Mitigación Rápida):
Si la actualización inmediata del sistema no es viable por motivos operativos, se debe desactivar la directiva session.upload_progress.enabled en el archivo de configuración php.ini y reiniciar el servicio Apache/PHP:

session.upload_progress.enabled = 0


Esta medida neutraliza por completo el vector de entrada sin afectar a las aplicaciones modernas que gestionan subidas mediante JavaScript/AJAX.

Reglas de Bloqueo en Servidor Web (.htaccess) y WAF:
Como control compensatorio en el perímetro (WAF como Cloudflare/ModSecurity) o en la configuración de Apache, se deben bloquear las peticiones multipart/form-data que contengan la cadena PHP_SESSION_UPLOAD_PROGRESS. Ejemplo de mitigación en .htaccess:

<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{HTTP:Content-Type} multipart/form-data [NC]
    RewriteRule ^ - [F,L]
</IfModule>


(Ajustando la regla para permitir únicamente los endpoints específicos que requieran subida legítima de archivos).

Endurecimiento de Arquitectura (Migración desde mod_php):
Reemplazar la arquitectura heredada de Apache Prefork con mod_php por PHP-FPM con aislamiento de procesos y configurar límites bajos en pm.max_requests para reciclar los procesos worker frecuentemente, reduciendo el riesgo de reutilización de memoria corrupta entre peticiones.

5. Conclusiones y Aprendizajes Obtenidos

El desarrollo del laboratorio PHP2Shell pone de manifiesto que la seguridad de un servicio web no depende únicamente de escribir código libre de vulnerabilidades a nivel de aplicación. Como se demostró durante las pruebas, un script tan simple e inofensivo como <?php echo "OK\n"; ?> puede convertirse en la puerta de entrada para el compromiso total del servidor si el intérprete subyacente (runtime) presenta fallos en la gestión de memoria durante etapas previas a la ejecución.

Asimismo, se comprende cómo dos debilidades técnicas distintas se encadenan para superar las defensas modernas del sistema operativo: mientras el fallo de divulgación de memoria (CVE-2026-109618) permite leer el estado interno del proceso a través de una cookie para derrotar la aleatorización de direcciones (ASLR), el fallo de corrupción de punteros (CVE-2026-109619) capitaliza esa información para desviar el flujo de ejecución hacia comandos del sistema. Esto reafirma la importancia crítica de mantener una gestión ágil de parches (Patch Management), aplicar el principio de mínima funcionalidad deshabilitando directivas innecesarias como session.upload_progress, y monitorear activamente las alertas de agotamiento de memoria en entornos de producción.

6. Confirmación de Finalización del Laboratorio

A continuación, se acredita la resolución del 100% de las tareas correspondientes a la sala PHP2Shell en la plataforma TryHackMe:
