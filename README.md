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
