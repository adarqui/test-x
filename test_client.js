var _OTP = require('./OTP.js');

var OTP = new _OTP({});
OTP.setUserKey(process.argv[2]);
OTP.printPin();
OTP.timer();
