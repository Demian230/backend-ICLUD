const { verificarToken } = require("../services/token");
const prisma = require("../lib/prisma");

module.exports = async function requireAuth(req, res, next) {
    const [tipo, token] = String(req.headers.authorization || "").split(" ");
    const payload = tipo === "Bearer" && token ? verificarToken(token) : null;

    if (!payload) {
        return res.status(401).json({ error: "Tenés que iniciar sesión para hacer esto" });
    }

    try {
        const usuario = await prisma.usuario.findUnique({
            where: { id: payload.id },
            select: { estado: true }
        });

        if (!usuario || !usuario.estado) {
            return res.status(403).json({ error: "Tu cuenta está bloqueada" });
        }
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: "Error al verificar la sesión" });
    }

    req.usuario = payload;
    next();
};