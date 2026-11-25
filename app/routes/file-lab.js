const fs = require("fs");
const path = require("path");

const BASE_DIR = path.resolve(__dirname, "../../artifacts/docs");
const ALLOWED_DOCS = ["readme.txt", "terms.txt", "faq.txt"];

// Path traversal test cases. Each handler is one case, named in the comment
// above it. EXPLOITABLE cases can read files outside the base directory, SAFE
// cases open files the same way but cannot leave it.
function FileLabHandler() {
    "use strict";

    const sendFile = (res, next) => function (err, data) {
        if (err) return next(err);
        return res.send(data);
    };

    const sendDone = (res, next) => function (err) {
        if (err) return next(err);
        return res.sendStatus(204);
    };

    // EXPLOITABLE 1: query string value joined to the base directory with no check
    this.read = (req, res, next) => {
        const name = req.query.name;
        const filePath = path.join(BASE_DIR, name);
        fs.readFile(filePath, "utf8", sendFile(res, next));
    };

    // EXPLOITABLE 2: route parameter used as the whole path
    this.stream = (req, res) => {
        const target = req.params.target;
        fs.createReadStream(target).pipe(res);
    };

    // EXPLOITABLE 3: request body value used as a path for a write
    this.save = (req, res, next) => {
        const name = req.body.name;
        fs.writeFile(BASE_DIR + "/" + name, req.body.content, sendDone(res, next));
    };

    // EXPLOITABLE 4: a "../" filter that "....//" bypasses
    this.weak = (req, res, next) => {
        const cleaned = String(req.query.name).replace("../", "");
        const filePath = path.join(BASE_DIR, cleaned);
        fs.readFile(filePath, "utf8", sendFile(res, next));
    };

    // SAFE 1: resolved path must stay under the base directory
    this.readSafe = (req, res, next) => {
        const resolved = path.resolve(BASE_DIR, String(req.query.name));
        if (!resolved.startsWith(BASE_DIR + path.sep)) {
            return res.status(400).send("outside base directory");
        }
        return fs.readFile(resolved, "utf8", sendFile(res, next));
    };

    // SAFE 2: only names from a fixed allowlist are opened
    this.doc = (req, res, next) => {
        const name = req.query.name;
        if (!ALLOWED_DOCS.includes(name)) {
            return res.status(400).send("unknown document");
        }
        const filePath = path.join(BASE_DIR, name);
        return fs.readFile(filePath, "utf8", sendFile(res, next));
    };

    // SAFE 3: the value must be a plain name of letters and digits, no separator or dots
    this.plain = (req, res, next) => {
        const name = req.query.name;
        if (!/^[A-Za-z0-9_]+$/.test(name)) {
            return res.status(400).send("invalid name");
        }
        const filePath = path.join(BASE_DIR, name + ".txt");
        return fs.readFile(filePath, "utf8", sendFile(res, next));
    };

    // SAFE 4: the value only picks a number, the file name is built from it
    this.page = (req, res, next) => {
        const number = parseInt(req.query.number, 10);
        if (Number.isNaN(number)) {
            return res.status(400).send("invalid number");
        }
        const filePath = path.join(BASE_DIR, `page${number}.txt`);
        return fs.readFile(filePath, "utf8", sendFile(res, next));
    };
}

module.exports = FileLabHandler;
