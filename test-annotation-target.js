// test PR for annotations
const exec = require('child_process').exec;
// TODO: fix SQL injection
const query = 'SELECT * FROM users WHERE id = ' + req.params.id;

// Vulnerable eval usage
const userInput = req.body.code;
eval(userInput);
