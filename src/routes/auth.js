const express = require("express");
const bcrypt = require("bcrypt");
const { firmarToken } = require("../services/token");
const prisma = require("../lib/prisma");
const router = express.Router();

router.post("/login", async (req, res) => {

    try {

        const gmail = String(req.body.gmail || "").trim().toLowerCase();
        const password = req.body.password;

        if (!gmail || !password) {
            return res.status(400).json({ error: "Faltan credenciales" });
        }

        const usuario = await prisma.usuario.findFirst({
            where: { gmail: { equals: gmail, mode: "insensitive" } }
        });

        if (!usuario) {
            return res.status(401).json({ error: "Credenciales inválidas" });
        }

        const passwordValida = await bcrypt.compare(password, usuario.password);
        if (!passwordValida) {
            return res.status(401).json({ error: "Credenciales inválidas" });
        }

        if (!usuario.estado) {
            return res.status(403).json({ error: "Tu cuenta está bloqueada" });
        }

        if (!["admin", "hotelero", "usuario"].includes(usuario.estatus)) {
            return res.status(403).json({ error: "No tenés permisos para acceder" });
        }

        res.json({
            mensaje: "Acceso concedido",
            estatus: usuario.estatus,
            token: firmarToken(usuario),
            usuario: { id: usuario.id, gmail: usuario.gmail, estatus: usuario.estatus, estado: usuario.estado }
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Error al verificar credenciales"
        });

    }
});

router.post("/register", async (req, res) => {

    try {

        const gmail = String(req.body.gmail || "").trim().toLowerCase();
        const password = req.body.password;

        if (!gmail || !password) {
            return res.status(400).json({ error: "Completá el correo y la contraseña" });
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(gmail)) {
            return res.status(400).json({ error: "El correo no es válido" });
        }

        if (typeof password !== "string" || password.length < 6) {
            return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres" });
        }

        const existente = await prisma.usuario.findFirst({ where: { gmail: { equals: gmail, mode: "insensitive" } } });
        if (existente) {
            return res.status(409).json({ error: "Ese correo ya está registrado" });
        }

        const passwordHash = await bcrypt.hash(password, 10);

        const usuario = await prisma.usuario.create({
            data: {
                gmail,
                password: passwordHash,
                estatus: "usuario",
                estado: true
            }
        });

        res.status(201).json({
            mensaje: "Cuenta creada correctamente",
            usuario: { id: usuario.id, gmail: usuario.gmail, estatus: usuario.estatus, estado: usuario.estado }
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Error al registrar el usuario"
        });

    }
});

module.exports = router;
