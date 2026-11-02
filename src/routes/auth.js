router.post("/login", async (req, res) => {
    try {
        const { gmail, password } = req.body;

        if (!gmail || !password) {
            return res.status(400).json({ error: "Faltan credenciales" });
        }

        // Buscamos el usuario usando la columna 'gmail' de la base de datos
        const usuario = await prisma.usuario.findFirst({
            where: { gmail }
        });

        if (!usuario) {
            return res.status(401).json({ error: "Credenciales inválidas" });
        }

        // Verificamos la contraseña hasheada
        const passwordValida = await bcrypt.compare(password, usuario.password);
        if (!passwordValida) {
            return res.status(401).json({ error: "Credenciales inválidas" });
        }

        // Limpiamos el estatus para evitar problemas con espacios o mayúsculas
        const estatusUsuario = usuario.estatus ? usuario.estatus.trim().toLowerCase() : "";

        // Generamos el token incluyendo el estatus
        const token = jwt.sign(
            { userId: usuario.id, gmail: usuario.gmail, estatus: estatusUsuario },
            JWT_SECRET,
            { expiresIn: '2h' }
        );

        // Devolvemos el acceso junto con el estatus exacto de la base de datos
        return res.json({ 
            mensaje: "Acceso concedido", 
            token,
            estatus: estatusUsuario 
        });

    } catch (error) {
        console.error("Error en el login:", error);
        res.status(500).json({
            error: "Error al verificar credenciales"
        });
    }
});