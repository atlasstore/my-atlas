/**
 * generate-hash.js — ATLAS Admin Password Hasher
 * Run: node generate-hash.js
 * Copy the output hash into ADMIN_PASS_HASH in your .env
 */
"use strict";
const bcrypt   = require("bcrypt");
const readline = require("readline");

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
rl.question("Enter admin password to hash: ", async (pass) => {
  if (!pass || pass.length < 12) {
    console.error("Password must be at least 12 characters.");
    rl.close();
    process.exit(1);
  }
  const hash = await bcrypt.hash(pass, 12);
  console.log("\nYour ADMIN_PASS_HASH (copy this into .env):\n");
  console.log(hash);
  console.log();
  rl.close();
});
