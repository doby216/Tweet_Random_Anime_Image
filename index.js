const fs = require("fs");
const url = require("url");
const http = require("http");
const https = require("https");
const crypto = require("crypto");

const {response_type, client_id, code_challenge_method, scope, grant_type,client_secret, client_type,redirect_uri} = require("./auth/credentials.json");
const all_session = [];

const port = 3000;
const server = http.createServer();

server.on("listening", listen_handler);
server.listen(port);

function listen_handler(){
    console.log(`Now listening on port ${port}`);
}

server.on("request", request_handler);

function request_handler(req, res){
    console.log(`New Request from ${req.socket.remoteAddress} for ${req.url}`);
    if(req.url === "/"){
        const form = fs.createReadStream("html/index.html");
		res.writeHead(200, {"Content-Type": "text/html"});
		form.pipe(res);
    }
    else if (req.url.startsWith("/tweet?")){
        //get user input
        const user_input = new URL(req.url, `https://${req.headers.host}`).searchParams;
        const tweet_content = user_input.get("tweet_content");

        //create state, code_challenge and code_verifier
        const state = crypto.randomBytes(20).toString("hex");
        const verifier = base64URLEncode(crypto.randomBytes(32));
        const code_challenge = base64URLEncode(sha256(verifier));

        //record the state and user input to all_session
        all_session.push({state, verifier, tweet_content});

        //redirect to twitter to get authorization code
        redirect_to_twitter(state, code_challenge, res);
	}
    else if(req.url.startsWith("/receive_code")){
		const {code, state} = url.parse(req.url, true).query;
		let current_session = all_session.find(current_session => current_session.state === state);
        let current_verifier = current_session?.verifier;
        let tweet_content = current_session?.tweet_content;
        console.log({code, state, current_session});
        if(code === undefined || state === undefined || current_session === undefined){
			not_found(res);
			return;
		}

        //send POST request to twitter to get access_token
		send_access_token_request(code, current_verifier, tweet_content, res);
	}
    else{
		not_found(res);
    }
}

function redirect_to_twitter(state, code_challenge, res){
    const authorization_endpoint = "https://twitter.com/i/oauth2/authorize";
	console.log({response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method, scope});
    let uri = new URLSearchParams({response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method, scope}).toString();
	console.log(`302 Redirect to ${authorization_endpoint}?${uri}`);
    // temporary redirection to twitter to get user authorization
    res.writeHead(302, {Location: `${authorization_endpoint}?${uri}`})
	   .end();
}

function send_access_token_request(code, code_verifier, tweet_content, res){
	const token_endpoint = "https://api.twitter.com/2/oauth2/token";
	const post_data = new URLSearchParams({code, grant_type, client_id, redirect_uri, code_verifier,client_secret, client_type}).toString();
	console.log(`POST to ${token_endpoint}\nPOST Data:${post_data}`);
	let options = {
		method: "POST",
		headers:{
			"Content-Type":"application/x-www-form-urlencoded"
		}
	}
    //send POST token request to twitter
	https.request(
		token_endpoint, 
		options, 
		(token_stream) => process_stream(token_stream, receive_access_token, tweet_content, res)
	).end(post_data);
}

function receive_access_token(body, tweet_content, res){
	const {access_token, refresh_token} = JSON.parse(body);
    console.log(body);
    console.log({access_token, refresh_token});

    // second API call
    get_picture_url(access_token, tweet_content, res);
}

function get_picture_url(access_token, tweet_content, res){
    const picture_api_url = "https://api.waifu.im/search";
    console.log(`GET request sent to ${picture_api_url}`);
    const picture_url_request = https.request(picture_api_url);
    picture_url_request.on("response", stream => process_stream(stream, parse_pic_url, access_token, tweet_content, res));
    picture_url_request.end();
}

function parse_pic_url(data, access_token, tweet_content, res){
    const lookup = JSON.parse(data);
    const pic_url = lookup?.images[0]?.url;
    console.log({pic_url});
    //const width = lookup?.images[0]?.width;
    //const height = lookup?.images[0]?.height;
    //res.writeHead(200, {"Content-Type": "text/html"});
	//res.write(`<img src="${pic_url}" alt="waifu image" style="width:${width/5}px;height:${height/5}px;">`);
    
    //POST picture URL and tweet_content to twitter
    post_to_twitter(access_token, pic_url, tweet_content, res);
}

function post_to_twitter(access_token, pic_url, tweet_content, res){
    const tweet_endpoint = "https://api.twitter.com/2/tweets";
    const text = `${tweet_content}\nPicture URL:${pic_url}`;
    const post_data = JSON.stringify({text});
    console.log(`POST to ${tweet_endpoint}\nPOST Data:${post_data}`);
    let options = {
		method: "POST",
		headers:{
            "Content-Type": "application/json",
			Authorization: `Bearer ${access_token}`
		}
    }

    //send POST request to tweets endpoint with tweet_content and picture URL from second API
    https.request(
		tweet_endpoint, 
		options, 
		(tweet_stream) => process_stream(tweet_stream, receive_tweet_response, access_token, res)
	).end(post_data);
}

function receive_tweet_response(body, access_token,res){
    console.log({body});
    get_twitter_username(access_token,res);
}

function get_twitter_username(access_token, res){
    const username_endpoint = "https://api.twitter.com/2/users/me";
    console.log(`GET request sent to ${username_endpoint}`);
    let options = {
		method: "GET",
		headers:{
			Authorization: `Bearer ${access_token}`
		}
    }
    //request authorizaed user's username from twitter
    https.request(
		username_endpoint, 
		options, 
		(username_stream) => process_stream(username_stream, receive_username_response, res)
	).end();
}

function receive_username_response(body, res){
    const {data} = JSON.parse(body);
    console.log({data});
    const username = data?.username;
    //redirect to authorizaed user's home page and close the connection
    console.log(`302 Redirect to https://twitter.com/${username}`);
    res.writeHead(302, {Location:`https://twitter.com/${username}`}).end();
}

function process_stream (stream, callback , ...args){
	let body = "";
	stream.on("data", chunk => body += chunk);
	stream.on("end", () => callback(body, ...args));
}

function not_found(res){
	res.writeHead(404, {"Content-Type": "text/html"});
	res.end(`<h1>404 Not Found</h1>`);
}

function base64URLEncode(str) {
    return str.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function sha256(buffer) {
    return crypto.createHash('sha256').update(buffer).digest();
}
