# IP Checker (PHP + SQLite)

Aplicación migrada a **PHP puro** pensada para correr localmente con **XAMPP en Windows**.

## Qué incluye

- Login básico con usuario demo `admin / admin`.
- Registro de IPs (solo admin).
- Ping manual por IP o para todas.
- Vista principal con columna **Ubicación**.
- **Subventana de detalle** por IP (`Detalles`) con:
  - resumen completo arriba,
  - historial acumulado de ping (últimos 7 días) abajo.
- Se eliminó en la UI la salida cruda del `ping -a` para que no se amontone.
- Selector de fondo usando imágenes dentro de la carpeta `wallpaper/`.
- CSS renovado, más elegante y con **modo nocturno**.
- Botones de agregar/acciones en tamaño más compacto.

## Estructura

- `index.php` → backend + renderizado principal.
- `static/style.css` → estilos (light/dark).
- `wallpaper/` → coloca aquí tus imágenes (`.jpg`, `.png`, `.webp`, etc.).
- `data/ips.db` → base de datos SQLite (se crea sola).
- `data/` → carpeta autocreada al iniciar si no existe.

## Ejecutar con XAMPP (Windows)

1. Copia la carpeta del proyecto a:
   - `C:\xampp\htdocs\IP-Checker`
2. Inicia **Apache** desde el panel de XAMPP.
3. Abre en el navegador:
   - `http://localhost/IP-Checker/index.php`

> Nota: para que el ping funcione en Windows, Apache debe poder ejecutar el comando `ping`.

## Programar mantenimiento en Windows (sin cron)

En Windows se usa **Task Scheduler** (Programador de tareas).

La app ya expone un worker por CLI:

- `php index.php worker`

Ese comando procesa:

- auto-pings vencidos,
- escaneo diario después de las 13:00 (una sola vez por día).

### Opción rápida (recomendada): crear tarea con `schtasks`

1. Verifica ruta de PHP (ejemplo XAMPP):
   - `C:\xampp\php\php.exe`
2. Desde PowerShell o CMD (como administrador), crea la tarea:

```bat
schtasks /Create /SC MINUTE /MO 1 /TN "IP-Checker-Worker" /TR "\"C:\xampp\php\php.exe\" \"C:\xampp\htdocs\IP-Checker\index.php\" worker" /F
```

3. Probar ejecución manual:

```bat
schtasks /Run /TN "IP-Checker-Worker"
```

4. Ver estado:

```bat
schtasks /Query /TN "IP-Checker-Worker" /V /FO LIST
```

### Configuración sugerida de la tarea

- **Trigger**: cada 1 minuto.
- **Run whether user is logged on or not**.
- **Start in**: `C:\xampp\htdocs\IP-Checker`.
- **Program/script**: `C:\xampp\php\php.exe`.
- **Arguments**: `index.php worker`.
- **Conditions**: desactivar “Start the task only if the computer is on AC power” si aplica.

### Notas importantes

- Si la PC está apagada o suspendida, no corre ninguna tarea.
- Si quieres forzar que el scan diario apunte a un segmento específico,
  guarda en `app_settings` la clave `auto_scan_segment` (ejemplo: `192.168.56.0/24`).

## Credenciales demo

- Usuario: `admin`
- Contraseña: `admin`

## Wallpaper personalizado

Coloca archivos en:

- `wallpaper/`

Luego en la app, en **Personalizar fondo**, selecciona el archivo y aplica.


## ¿Dónde se guardan los datos?

- Se guardan en `data/ips.db` (SQLite).
- Sí, la carpeta `data/` se **autocrea** en el arranque de la app.
