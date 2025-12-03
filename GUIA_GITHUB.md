# Guía: Subir Proyecto a GitHub

## 📋 Pasos para Subir el Proyecto a GitHub

### Paso 1: Crear Repositorio en GitHub

1. **Ir a GitHub:**
   - Visita: https://github.com
   - Inicia sesión o crea una cuenta

2. **Crear nuevo repositorio:**
   - Click en el botón **"+"** (arriba derecha) → **"New repository"**
   - O visita directamente: https://github.com/new

3. **Configurar el repositorio:**
   - **Repository name:** `wifi-jammer-raspberry-pi` (o el nombre que prefieras)
   - **Description:** `WiFi Jammer adaptado para Raspberry Pi 4 con adaptador BrosTrend AC1200 AC3L`
   - **Visibility:** 
     - ✅ **Public** (si quieres que sea público)
     - ✅ **Private** (si quieres mantenerlo privado)
   - ⚠️ **NO marques** "Add a README file" (ya tenemos uno)
   - ⚠️ **NO marques** "Add .gitignore" (ya tenemos uno)
   - ⚠️ **NO marques** "Choose a license" (por ahora)
   - Click en **"Create repository"**

4. **Copiar la URL del repositorio:**
   - GitHub te mostrará una página con instrucciones
   - **Copia la URL** que aparece (algo como: `https://github.com/tu-usuario/wifi-jammer-raspberry-pi.git`)
   - La necesitarás en el siguiente paso

---

### Paso 2: Inicializar Git en el Proyecto Local

Abre una terminal en la carpeta del proyecto y ejecuta:

#### En Windows (PowerShell o CMD):

```powershell
# Navegar a la carpeta del proyecto
cd C:\Users\dberp\Downloads\cypher-cc1101-jammer-main\cypher-cc1101-jammer-main

# Verificar que estás en la carpeta correcta
dir
# Deberías ver: python_version, README.md, etc.

# Inicializar git (si no está inicializado)
git init

# Verificar estado
git status
```

#### En Linux/Mac:

```bash
# Navegar a la carpeta del proyecto
cd ~/Downloads/cypher-cc1101-jammer-main/cypher-cc1101-jammer-main

# Verificar que estás en la carpeta correcta
ls
# Deberías ver: python_version, README.md, etc.

# Inicializar git (si no está inicializado)
git init

# Verificar estado
git status
```

---

### Paso 3: Configurar Git (si es primera vez)

```bash
# Configurar tu nombre (reemplaza con tu nombre)
git config --global user.name "Tu Nombre"

# Configurar tu email (reemplaza con tu email de GitHub)
git config --global user.email "tu-email@ejemplo.com"

# Verificar configuración
git config --list
```

**Nota:** Si ya tienes Git configurado, puedes saltar este paso.

---

### Paso 4: Agregar Archivos al Repositorio

```bash
# Agregar todos los archivos (excepto los del .gitignore)
git add .

# Verificar qué se va a subir
git status

# Deberías ver todos los archivos listos para commit
```

**Archivos que se subirán:**
- ✅ Todo el código Python
- ✅ README.md y documentación
- ✅ requirements.txt
- ✅ Archivos de configuración
- ✅ Imágenes y recursos

**Archivos que NO se subirán (gracias al .gitignore):**
- ❌ `__pycache__/` (archivos compilados)
- ❌ `venv/` (entorno virtual)
- ❌ `*.dat` (archivos de datos)
- ❌ `*.pcap` (capturas)
- ❌ `.wifi_jammer_history` (historial)

---

### Paso 5: Hacer el Primer Commit

```bash
# Crear el commit inicial
git commit -m "Initial commit: WiFi Jammer para Raspberry Pi 4

- Adaptación completa del proyecto CC1101 a WiFi
- Soporte para adaptador BrosTrend AC1200 AC3L
- Versión Python con mejoras de performance
- Documentación completa incluida"
```

**Nota:** El mensaje del commit puede ser más simple si prefieres:
```bash
git commit -m "Initial commit"
```

---

### Paso 6: Conectar con el Repositorio Remoto

```bash
# Agregar el repositorio remoto (reemplaza con TU URL)
git remote add origin https://github.com/TU-USUARIO/TU-REPOSITORIO.git

# Verificar que se agregó correctamente
git remote -v
# Debería mostrar:
# origin  https://github.com/TU-USUARIO/TU-REPOSITORIO.git (fetch)
# origin  https://github.com/TU-USUARIO/TU-REPOSITORIO.git (push)
```

**⚠️ IMPORTANTE:** Reemplaza `TU-USUARIO` y `TU-REPOSITORIO` con los valores reales de tu repositorio.

**Ejemplo:**
```bash
git remote add origin https://github.com/juanperez/wifi-jammer-raspberry-pi.git
```

---

### Paso 7: Subir el Proyecto a GitHub

```bash
# Subir el código (primera vez)
git branch -M main
git push -u origin main
```

**Si GitHub te pide autenticación:**

#### Opción A: Personal Access Token (Recomendado)

1. **Crear un token:**
   - Ve a: https://github.com/settings/tokens
   - Click en **"Generate new token"** → **"Generate new token (classic)"**
   - Nombre: `wifi-jammer-project`
   - Selecciona permisos: ✅ **repo** (todos los permisos de repo)
   - Click en **"Generate token"**
   - **⚠️ COPIA EL TOKEN INMEDIATAMENTE** (solo se muestra una vez)

2. **Usar el token:**
   ```bash
   # Cuando te pida usuario: tu-usuario-de-github
   # Cuando te pida contraseña: PEGA-EL-TOKEN-AQUI
   ```

#### Opción B: GitHub CLI (Alternativa)

```bash
# Instalar GitHub CLI (si no lo tienes)
# Windows: winget install GitHub.cli
# Linux: sudo apt install gh
# Mac: brew install gh

# Autenticarse
gh auth login

# Luego hacer push normalmente
git push -u origin main
```

---

### Paso 8: Verificar que se Subió Correctamente

1. **Ir a tu repositorio en GitHub:**
   - Visita: `https://github.com/TU-USUARIO/TU-REPOSITORIO`
   - Deberías ver todos los archivos

2. **Verificar estructura:**
   - ✅ Debe aparecer `python_version/` con todos los archivos
   - ✅ Debe aparecer `README.md`
   - ✅ Debe aparecer `.gitignore`
   - ✅ No debe aparecer `venv/` ni `__pycache__/`

---

## 🔄 Comandos para Futuras Actualizaciones

Una vez subido, para actualizar el repositorio:

```bash
# Ver qué archivos cambiaron
git status

# Agregar cambios
git add .

# O agregar archivos específicos
git add archivo1.py archivo2.py

# Hacer commit
git commit -m "Descripción de los cambios"

# Subir cambios
git push
```

---

## 📝 Comandos Útiles de Git

```bash
# Ver historial de commits
git log

# Ver diferencias antes de commit
git diff

# Ver estado actual
git status

# Deshacer cambios en un archivo (antes de git add)
git checkout -- archivo.py

# Deshacer git add (pero mantener cambios)
git reset HEAD archivo.py

# Ver ramas
git branch

# Crear nueva rama
git branch nombre-rama

# Cambiar de rama
git checkout nombre-rama
```

---

## ⚠️ Solución de Problemas

### Error: "remote origin already exists"

```bash
# Eliminar el remote existente
git remote remove origin

# Agregar el correcto
git remote add origin https://github.com/TU-USUARIO/TU-REPOSITORIO.git
```

### Error: "failed to push some refs"

```bash
# Si alguien más hizo cambios (o creaste README en GitHub)
git pull origin main --allow-unrelated-histories

# Luego intentar push de nuevo
git push -u origin main
```

### Error: "authentication failed"

- Verifica que el token esté correcto
- Asegúrate de usar el token como contraseña, no tu contraseña de GitHub
- Si expiró, crea uno nuevo

### Error: "repository not found"

- Verifica que la URL del repositorio sea correcta
- Verifica que tengas permisos en el repositorio
- Verifica que el repositorio exista

---

## ✅ Checklist Final

Antes de considerar que todo está listo:

- [ ] Repositorio creado en GitHub
- [ ] Git inicializado en el proyecto local
- [ ] `.gitignore` creado y funcionando
- [ ] Archivos agregados (`git add .`)
- [ ] Primer commit realizado
- [ ] Repositorio remoto agregado
- [ ] Código subido exitosamente (`git push`)
- [ ] Verificado en GitHub que todos los archivos están presentes
- [ ] Verificado que archivos sensibles NO están en el repositorio

---

## 🎉 ¡Listo!

Una vez completados estos pasos, tu proyecto estará en GitHub y podrás:

1. **Clonarlo en la Raspberry Pi:**
   ```bash
   git clone https://github.com/TU-USUARIO/TU-REPOSITORIO.git
   ```

2. **Compartirlo con otros**
3. **Tener backup en la nube**
4. **Colaborar con otros desarrolladores**

---

## 📞 ¿Necesitas Ayuda?

Si encuentras algún problema:

1. Revisa los mensajes de error (suelen ser descriptivos)
2. Verifica que todos los pasos se hayan seguido correctamente
3. Consulta la documentación de Git: https://git-scm.com/doc
4. Consulta la documentación de GitHub: https://docs.github.com

¡Buena suerte con tu proyecto! 🚀

