var
	cron = require('cron').CronJob,
	crypto = require('crypto');


var _OTP = function(opts) {
	var OTP = this;

	OTP.opts = opts;
	OTP.state = {
		cron : {},
		key : "nothing",
	}

	OTP.setUserKey = function(key) {
		OTP.state.key = key;
	}

	OTP.genTime = function() {
		var d = new Date();
		/*
		console.log(d.getUTCFullYear(),d.getUTCMonth(),d.getUTCDate(),d.getUTCHours(),d.getUTCMinutes());
		*/
		d = d.getUTCFullYear().toString() + d.getUTCMonth().toString() + d.getUTCDate().toString() + d.getUTCHours().toString() + d.getUTCMinutes().toString();
		console.log("genTime=",d);
		return d;
	}

	OTP.genPin = function(s,len) {

		var new_key = OTP.state.key+s;

		console.log("generating pin for: ", new_key);
		var sha = crypto.createHash('sha512');
		sha.update(OTP.state.key+s, 'utf8');
		var res = sha.digest('hex');
		var sub = res.substring(0,len);
		sub = sub.replace(/a/g,0).replace(/b/g,1).replace(/c/g,2).replace(/d/g,3).replace(/e/g,4).replace(/f/g,5);
		return sub;
	}


	OTP.printPin = function() {
		var d = OTP.genTime();
		var pin = OTP.genPin(d.toString(),8);
		console.log("pin",pin);
	},

	OTP.timer = function() {
		OTP.state.cron = new cron('0 * * * * *', function() {
			OTP.printPin();
		}, null, true, "America/New_York");
	}

	OTP.genKeys = function() {
		var priv = ursa.generatePrivateKey(4096, 3);
		OTP.state.key.obj = priv;
		OTP.state.key.private = priv.toPrivatePem().toString();
		OTP.state.key.public = priv.toPublicPem().toString();
	}

	OTP.init = function() {
	}

	OTP.init();
}


module.exports = _OTP;
