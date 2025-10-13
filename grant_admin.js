const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("./checkcheats.db");
db.run("UPDATE users SET role = ? WHERE email = ?", ["admin", "prorok161009@gmail.com"], (err) => {
    if (err) console.error(err);
    else console.log("Admin role granted!");
    db.close();
});
