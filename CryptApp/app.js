'use strict';
var crypt = require("./crypt");

var myArgs = process.argv.slice(2);

//console.log(myArgs);
crypt.des_init();
console.log(crypt.descrypt(myArgs[0], myArgs[1]));

return crypt.descrypt(myArgs[0], myArgs[1]);
