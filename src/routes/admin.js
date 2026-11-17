const express = require("express");
const prisma = require("../lib/prisma");
const requireAuth = require("../middleware/requireAuth");

const router = express.Router();

router.get("/usuarios", requireAuth, async (req, res) => {
    try {
        const usuarios = await prisma.usuario.findMany({
            where: { estatus: { not: "admin" } },
            select: { id: true, gmail: true, estatus: true, estado: true },
            orderBy: { id: "asc" }
        });
        return res.json(usuarios);
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: "Error al obtener los usuarios" });
    }
});

router.patch("/usuarios/:id/estado", requireAuth, async (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) {
        return res.status(400).json({ error: "El id del usuario no es válido" });
    }

    if (typeof req.body.estado !== "boolean") {
        return res.status(400).json({ error: "El estado debe ser true (desbloqueado) o false (bloqueado)" });
    }

    if (id === req.usuario.id) {
        return res.status(400).json({ error: "No podés bloquear tu propia cuenta" });
    }

    try {
        const usuario = await prisma.usuario.update({
            where: { id },
            data: { estado: req.body.estado },
            select: { id: true, gmail: true, estatus: true, estado: true }
        });

        return res.json({
            mensaje: req.body.estado ? "Usuario desbloqueado correctamente" : "Usuario bloqueado correctamente",
            usuario
        });
    } catch (error) {
        if (error.code === "P2025") {
            return res.status(404).json({ error: "No se encontró el usuario" });
        }
        console.error(error);
        return res.status(500).json({ error: "Error al modificar el estado del usuario" });
    }
});

module.exports = router;