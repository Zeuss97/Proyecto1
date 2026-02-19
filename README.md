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

## Mejoras de rendimiento (OPcache + APCu)

Para mejorar tiempos de respuesta en navegación y dashboard:

- **OPcache** acelera ejecución de PHP (bytecode cache).
- **APCu** habilita caché en memoria para estadísticas del dashboard (con fallback automático si APCu no está instalado).

### 1) Activar OPcache en XAMPP

En `C:\xampp\php\php.ini`, verifica:

```ini
[opcache]
zend_extension=opcache
opcache.enable=1
opcache.enable_cli=0
opcache.memory_consumption=192
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=20000
opcache.validate_timestamps=1
opcache.revalidate_freq=2
```

### 2) Activar APCu en XAMPP

1. Copia la DLL compatible (`php_apcu.dll`) en `C:\xampp\php\ext\`.
2. En `php.ini` agrega:

```ini
extension=php_apcu.dll

[apcu]
apc.enabled=1
apc.shm_size=128M
apc.ttl=300
apc.gc_ttl=300
apc.entries_hint=4096
; opcional para CLI (si quieres cache también en `php index.php worker`)
apc.enable_cli=0
```

3. Reinicia Apache desde XAMPP.

### 3) Verificar módulos

```bat
C:\xampp\php\php.exe -m | findstr /I "opcache apcu"
C:\xampp\php\php.exe -i | findstr /I "opcache.enable apc.enabled"
```

### 4) Ajuste recomendado de operación

- Mantener `php index.php worker` programado por Task Scheduler.
- Dejar deshabilitado el mantenimiento por request web (setting `enable_web_maintenance=0`) para menor latencia de UI.

## Credenciales demo

- Usuario: `admin`
- Contraseña: `admin`

## Wallpaper personalizado

Coloca archivos en:

- `wallpaper/`

Luego en la app, en **Personalizar fondo**, selecciona el archivo y aplica.
