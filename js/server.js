const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const db = new sqlite3.Database("./usuarios.db");

db.run(`
  CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    senha TEXT NOT NULL
  )
`);

app.post("/cadastro", async (req, res) => {
  const { nome, email, senha } = req.body;

  const senhaCriptografada = await bcrypt.hash(senha, 10);

  db.run(
    "INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)",
    [nome, email, senhaCriptografada],
    function (erro) {
      if (erro) {
        return res.status(400).json({ mensagem: "E-mail já cadastrado" });
      }

      res.json({ mensagem: "Usuário cadastrado com sucesso!" });
    }
  );
});

app.post("/login", (req, res) => {
  const { email, senha } = req.body;

  db.get(
    "SELECT * FROM usuarios WHERE email = ?",
    [email],
    async (erro, usuario) => {
      if (!usuario) {
        return res.status(400).json({ mensagem: "Usuário não encontrado" });
      }

      const senhaCorreta = await bcrypt.compare(senha, usuario.senha);

      if (!senhaCorreta) {
        return res.status(400).json({ mensagem: "Senha incorreta" });
      }

      res.json({ mensagem: "Login realizado com sucesso!", usuario: usuario.nome });
    }
  );
});

app.listen(3000, () => {
  console.log("Servidor rodando na porta 3000");
});