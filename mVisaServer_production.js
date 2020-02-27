var express = require('express');
var logger = require('./logger/logger.js').logger;
var app = express();
var webConfig = require('./config.js');
var bodyParser  = require('body-parser');
var http = require("http");
var https = require("https");
var fs = require("fs");
var request = require('request');
var crypto = require('crypto');


try {
	// parse application/x-www-form-urlencoded 
	app.use(bodyParser.urlencoded({ extended: false }))
	// parse application/json 
	app.use(bodyParser.json())

}catch(e){
	logger.log('error', 'Bodyparser Error :' + err.toString());
	res.status(401).send({"error_id":"500","error_description":"Invalid Request"});
	res.end;
	return;
}
app.use('/icons', express.static((__dirname, 'icons')));
app.use('/apk', express.static((__dirname, 'apk')));
app.use('/tnc', express.static((__dirname, 'tnc')));

app.use("/",function(req,res,next){
	console.log(req.method+" "+req.originalUrl.toString());
	res.header("Access-Control-Allow-Origin", "*");
       res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
	var sql1 = /'/g ;
	var sql2 = /--/g;
	for(var i in req.body){
	   //console.log(i+"=="+req.body[i]);
	   if(req.body[i] && typeof req.body[i] == "string" && (req.body[i].match(sql1) ||  req.body[i].match(sql2))){
		   	logger.log('error', req.method +' PATH='+req.originalUrl.toString()+' (req=' + JSON.stringify(req.body) + ')] Injection dectected');
			res.send({"error": "101", "error_description": "Invalid Request"});
            res.end;
			return;
	    }
	}
	next();
});

app.get('/test',function(req,res){
	res.send({"error": "101", "error_description": "Invalid Request"});

});
app.use("/", function(req, res) {
    console.log("Forwarded  to App "+req.originalUrl.toString().replace("/MVisa", ""));
    var headers = {};
    headers["Content-Type"] = "application/json";

    if (req.headers.auth_token)
        headers["auth_token"] = req.headers.auth_token;

    if (req.headers.admin_auth_token)
        headers["admin_auth_token"] = req.headers.admin_auth_token;

	if (req.headers.pltn)
	headers["pltn"] = req.headers.pltn;

	if (req.headers.version_code)
	headers["version_code"] = req.headers.version_code;
	
	if (req.headers.version_name)
	headers["version_name"] = req.headers.version_name;


	console.log(webConfig.appServerAddr+"===="+webConfig.appServerPort);
    var options = {
        host: webConfig.appServerAddr,
        path: req.originalUrl.toString().replace("/MVisa", ""),
        port: webConfig.appServerPort,
        method: "POST",
        headers: headers
    };

    
	
   try{	
    
    
    	if(req.method=="GET"){	
		var url = "http://"+webConfig.appServerAddr+":"+webConfig.appServerPort+""+req.originalUrl.toString().replace("/MVisa", "");
		
		getRequest({url:url,headers:headers},req.body,function(err,body){
			
			if(err){
			   	logger.log('error', req.method +' PATH='+req.originalUrl.toString()+' (req=' + JSON.stringify(req.body) + ')] '+err.toString());
				return res.status(500).send(JSON.stringify({errCode:"501",message:err.toString()}));	
			}else{
				console.log(body);
			   	logger.log('info', req.method +' PATH='+req.originalUrl.toString()+' (req=' + JSON.stringify(req.body) + ')] SUCCESS');
				return res.status(200).send(body);
			}
		})	
	}else{	
		var httpreq = http.request(options, function(response) {
			response.setEncoding("utf8");
			var resBody="";
			response.on('data', function(chunk) {
			    resBody +=chunk;
			});
			response.on('end', function() {
				console.log("+++++++++++++++++++++++++++++++++++++++++++Response from Appserver STARTS+++++++++++++++++++++++++++++++++++++++++++");
				console.log(resBody);
			    console.log("+++++++++++++");
			    resBody = JSON.parse(resBody);
				//Add PayLoad header+++++++++++++++
				res.setHeader('pltn',generatePayload(JSON.stringify(resBody)));
				/*++++++++++++++++++++++++++++++++*/
				logger.log('info', '++++++Response from Appserver++++'+JSON.stringify(resBody));
				
				if(req.originalUrl.toString().indexOf("aeps")!= -1)
					logger.log('info', req.method +' PATH='+req.originalUrl.toString()  + ')] SUCCESS');
				else
			   		logger.log('info', req.method +' PATH='+req.originalUrl.toString()+' (req=' + JSON.stringify(req.body) + ')] SUCCESS');
			    return res.status(200).send(JSON.stringify(resBody));	
			});
			response.on('error', function() {
			   	logger.log('error', req.method +' PATH='+req.originalUrl.toString()+' (req=' + JSON.stringify(req.body) + ')] Request Error');
			    return res.status(500).send(JSON.stringify({
					errCode: "501",
					message: "Failure"
			    }));
			});
		 });
  		httpreq.write(JSON.stringify(req.body));
	   	httpreq.end();
 
   	}
   }catch(e){
	   	logger.log('error', req.method +' PATH='+req.originalUrl.toString()+' (req=' + JSON.stringify(req.body) + ')] ' +e.toString());
		return res.status(500).send(JSON.stringify({errCode:"501",message:e.toString()}));	
   }

});

function generatePayload(reqJSON)
{
	try
	{
		console.log("+++++++++Inside generatePayload Function++++++++++");
	//	var buffer = new Buffer(webConfig.hmac_key, 'utf8');
	//	var base64_key = buffer.toString('base64');
		var hmac_hmac = crypto.createHmac('sha256', webConfig.hmac_key);
		hmac_hmac.update(reqJSON,'utf8');
		var payload=hmac_hmac.digest('base64');
		console.log("+++++++++Payload++++++++++: "+payload);
		return payload; 
		
	}
	catch (Exception)
	{
		 	logger.log('error', 'Exception in generatePayload Catch Block'+Exception.toString());
		console.log("Exception in generatePayload Catch Block:"+Exception);
		return Exception;
	}
}

function getRequest(options,reqBody,callback){
	



	request({url:options.url, qs:reqBody,headers:options.headers}, function(err, response, body) {
	  if(err) { 
		console.log("Err in getRequest unction "+err.toString());
		callback(err,null);
	  }else{
		callback(null,body);
	  }
	  
	});

}

app.use(function(err, req, res, next) {
  
  if(err){
  	logger.log('error', req.method +' PATH='+req.originalUrl.toString()+' (req=' + JSON.stringify(req.body) + ')] ' +err.toString());
	return res.status(500).send(JSON.stringify({errCode:"501",message:err.toString()}));	
  }
});




module.exports = app
app.listen(3944);
console.log('Mobile Web Server started'+webConfig.webMobServerPort);
logger.log('info', 'Mobile Web server started at 192.168.83.250:'+webConfig.webMobServerPort);
/*
var ciphers = [
"ECDHE-RSA-AES128-GCM-SHA256",
"ECDHE-ECDSA-AES128-GCM-SHA256",
"ECDHE-RSA-AES256-GCM-SHA384",
"ECDHE-ECDSA-AES256-GCM-SHA384",
"DHE-RSA-AES128-GCM-SHA256",
"ECDHE-RSA-AES128-SHA256",
"DHE-RSA-AES128-SHA256",
"ECDHE-RSA-AES256-SHA384",
"DHE-RSA-AES256-SHA384",
"ECDHE-RSA-AES256-SHA256",
"DHE-RSA-AES256-SHA256",
"!aNULL",
"!DES",
"!eNULL",
"!EXPORT",
"!RC4",
"!MD5",
"!PSK",
"!SRP",
"!CAMELLIA",
"AES128-SHA256",
"AES256-SHA256",
"AES128-GCM-SHA256",
"AES256-GCM-SHA384",
"DH-RSA-AES128-SHA256",
"DH-RSA-AES256-SHA256",
"DH-RSA-AES128-GCM-SHA256",
"DH-RSA-AES256-GCM-SHA384",
"DH-DSS-AES128-SHA256",
"DH-DSS-AES256-SHA256",
"DH-DSS-AES128-GCM-SHA256",
"DH-DSS-AES256-GCM-SHA384",
"DHE-RSA-AES128-SHA256",
"DHE-RSA-AES256-SHA256",
"DHE-RSA-AES128-GCM-SHA256",
"DHE-RSA-AES256-GCM-SHA384",
"DHE-DSS-AES128-SHA256",
"DHE-DSS-AES256-SHA256",
"DHE-DSS-AES128-GCM-SHA256",
"DHE-DSS-AES256-GCM-SHA384",
"ECDH-RSA-AES128-SHA256",
"ECDH-RSA-AES256-SHA384",
"ECDH-RSA-AES128-GCM-SHA256",
"ECDH-RSA-AES256-GCM-SHA384",
"ECDH-ECDSA-AES128-SHA256",
"ECDH-ECDSA-AES256-SHA384",
"ECDH-ECDSA-AES128-GCM-SHA256",
"ECDH-ECDSA-AES256-GCM-SHA384",
"ECDHE-RSA-AES128-SHA256",
"ECDHE-RSA-AES256-SHA384",
"ECDHE-RSA-AES128-GCM-SHA256",
"ECDHE-RSA-AES256-GCM-SHA384",
"ECDHE-ECDSA-AES128-SHA256",
"ECDHE-ECDSA-AES256-SHA384",
"ECDHE-ECDSA-AES128-GCM-SHA256",
"ECDHE-ECDSA-AES256-GCM-SHA384",
"ADH-AES128-SHA256",
"ADH-AES256-SHA256",
"ADH-AES128-GCM-SHA256",
"ADH-AES256-GCM-SHA384",
"AES128-SHA",
"AES256-SHA",
"DH-DSS-AES128-SHA",
"DH-DSS-AES256-SHA",
"DH-RSA-AES128-SHA",
"DH-RSA-AES256-SHA",
"DHE-DSS-AES128-SHA",
"DHE-DSS-AES256-SHA",
"DHE-RSA-AES128-SHA",
"DHE-RSA-AES256-SHA",
"ADH-AES128-SHA",
"ADH-AES256-SHA",
"ECDH-RSA-NULL-SHA",
"ECDH-RSA-RC4-SHA",
//"ECDH-RSA-DES-CBC3-SHA",
"ECDH-RSA-AES128-SHA",
"ECDH-RSA-AES256-SHA",
"ECDH-ECDSA-NULL-SHA",
"ECDH-ECDSA-RC4-SHA",
//"ECDH-ECDSA-DES-CBC3-SHA",
"ECDH-ECDSA-AES128-SHA",
"ECDH-ECDSA-AES256-SHA",
"ECDHE-RSA-NULL-SHA",
"ECDHE-RSA-RC4-SHA",
//"ECDHE-RSA-DES-CBC3-SHA",
"ECDHE-RSA-AES128-SHA",
"ECDHE-RSA-AES256-SHA",
"ECDHE-ECDSA-NULL-SHA",
"ECDHE-ECDSA-RC4-SHA",
//"ECDHE-ECDSA-DES-CBC3-SHA",
"ECDHE-ECDSA-AES128-SHA",
"ECDHE-ECDSA-AES256-SHA",
"AECDH-NULL-SHA",
"AECDH-RC4-SHA",
//"AECDH-DES-CBC3-SHA",
"AECDH-AES128-SHA",
"AECDH-AES256-SHA"
].join(':');

https.createServer({
      pfx: fs.readFileSync('../cert/mvisamobile.hdfcbank.com.pfx'),
      passphrase: '',
      requestCert: true,
	  ciphers: ciphers,
      rejectUnauthorized: false,
	  secureProtocol: "TLSv1_2_method",
	  honorCipherOrder: true
    }, app).listen(webConfig.webMobServerPort);
logger.log('info', 'Mobile SSl server started at 172.21.1.187:'+webConfig.webMobServerPort);
*/
process.on('uncaughtException', function (err) {
    console.log("++++ERROR on App router +++++++++");	
    console.log(err);
	logger.log('error', 'Process Error : '+err.toString());
    console.log("+++++++++++++++++++++++++++++++++");
});
