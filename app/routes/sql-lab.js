const mysql = require("mysql");

const pool = mysql.createPool({
    host: process.env.SQL_LAB_HOST || "localhost",
    user: process.env.SQL_LAB_USER || "root",
    password: process.env.SQL_LAB_PASSWORD || "",
    database: process.env.SQL_LAB_DB || "lab"
});

const SORT_COLUMNS = ["id", "name", "created_at"];

// SQL injection test cases. Each handler is one case, named in the comment
// above it. EXPLOITABLE cases can be attacked, SAFE cases build the query the
// same way but the value cannot carry SQL.
function SqlLabHandler() {
    "use strict";

    const send = (res, next) => (err, rows) => {
        if (err) return next(err);
        return res.json(rows);
    };

    // EXPLOITABLE 1: query string value placed inside quotes in a WHERE clause
    this.userByName = (req, res, next) => {
        const name = req.query.name;
        const query = `SELECT * FROM users WHERE name = '${name}'`;
        pool.query(query, send(res, next));
    };

    // EXPLOITABLE 2: route parameter concatenated into a LIKE search
    this.search = (req, res, next) => {
        const term = req.params.term;
        const query = "SELECT * FROM products WHERE title LIKE '%" + term + "%'";
        pool.query(query, send(res, next));
    };

    // EXPLOITABLE 3: request body value placed in ORDER BY with no allowlist
    this.sorted = (req, res, next) => {
        const column = req.body.column;
        const query = `SELECT * FROM users ORDER BY ${column}`;
        pool.query(query, send(res, next));
    };

    // EXPLOITABLE 4: query string value placed in a DELETE statement
    this.remove = (req, res, next) => {
        const id = req.query.id;
        const query = `DELETE FROM notes WHERE id = ${id}`;
        pool.query(query, send(res, next));
    };

    // SAFE 1: ORDER BY column is checked against a fixed allowlist first
    this.sortedSafe = (req, res, next) => {
        const column = req.body.column;
        if (!SORT_COLUMNS.includes(column)) {
            return res.status(400).json({ error: "unsupported column" });
        }
        const query = `SELECT * FROM users ORDER BY ${column}`;
        return pool.query(query, send(res, next));
    };

    // SAFE 2: the id is converted to an integer, so only digits reach the query
    this.userById = (req, res, next) => {
        const id = parseInt(req.params.id, 10);
        if (Number.isNaN(id)) {
            return res.status(400).json({ error: "invalid id" });
        }
        const query = `SELECT * FROM users WHERE id = ${id}`;
        return pool.query(query, send(res, next));
    };

    // SAFE 3: the term is stripped to letters and digits before it is used
    this.searchSafe = (req, res, next) => {
        const term = String(req.query.term).replace(/[^A-Za-z0-9]/g, "");
        const query = `SELECT * FROM products WHERE title LIKE '%${term}%'`;
        return pool.query(query, send(res, next));
    };

    // SAFE 4: the limit is a number clamped to a range
    this.top = (req, res, next) => {
        const limit = Math.max(1, Math.min(100, Number(req.query.count) || 10));
        const query = `SELECT * FROM users LIMIT ${limit}`;
        return pool.query(query, send(res, next));
    };
}

module.exports = SqlLabHandler;
