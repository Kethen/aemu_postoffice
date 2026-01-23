const net = require('node:net');
const http = require('node:http');
const port = 27313
const status_port = 27314;
const statistic_interval_ms = 1000 * 60 * 2;

const AEMU_POSTOFFICE_INIT_PDP = 0;
const AEMU_POSTOFFICE_INIT_PTP_LISTEN = 1;
const AEMU_POSTOFFICE_INIT_PTP_CONNECT = 2;
const AEMU_POSTOFFICE_INIT_PTP_ACCEPT = 3;

process.on('SIGTERM', () => {
   process.exit(1); 
});

process.on('SIGINT', () => {
   process.exit(1); 
});

let sessions = {};

let get_mac_str = (mac) => {
	let ret = ""
	for (i = 0;i < 6;i++){
		if (i != 0){
			ret = ret + ":";
		}
		ret = ret + mac.slice(i, i + 1).toString("hex");
	}
	return ret;
}

let get_sock_addr_str = (sock) => {
	return `${sock.remoteAddress}:${sock.remotePort}`
}

let server = net.createServer();

server.maxConnections = 1000;

server.on("error", (err) => {
	throw err;
});

let log = (str) => {
	console.log(`${new Date()}: ${str}`)
};

server.on("drop", (drop) => {
	log(`connection dropped as we have reached ${server.maxConnections} connections:`);
	log(drop);
});

// simple tracking per interval statistics for now, a better picture requires a database
let statistics = {};

// don't pull statistics into a scope with arrow function
function get_statistics_obj(ip){
	let existing_obj = statistics[ip];
	if (existing_obj != undefined){
		return existing_obj;
	}
	let new_obj = {
		ptp_connects:0,
		ptp_listen_connects:0,
		ptp_tx:0,
		ptp_tx_ops:0,
		ptp_rx:0,
		ptp_rx_ops:0,
		pdp_connects:0,
		pdp_tx:0,
		pdp_tx_ops:0,
		pdp_rx:0,
		pdp_rx_ops:0
	};
	statistics[ip] = new_obj;
	return new_obj;
}

let track_connect = (ip, is_ptp, is_listen) => {
	let statistics_obj = get_statistics_obj(ip);
	if (is_ptp){
		if (is_listen){
			statistics_obj.ptp_listen_connects++;
		}else{
			statistics_obj.ptp_connects++;
		}
	}else{
		statistics_obj.pdp_connects++;
	}
}

let track_bandwidth = (ip, is_ptp, is_tx, size) => {
	let statistics_obj = get_statistics_obj(ip);
	if (is_ptp){
		if (is_tx){
			statistics_obj.ptp_tx += size;
			statistics_obj.ptp_tx_ops++;
		}else{
			statistics_obj.ptp_rx += size;
			statistics_obj.ptp_rx_ops++;
		}
	}else{
		if (is_tx){
			statistics_obj.pdp_tx += size;
			statistics_obj.pdp_tx_ops++;
		}else{
			statistics_obj.pdp_rx += size;
			statistics_obj.pdp_rx_ops++;
		}
	}
}

// don't pull statistics into a scope with arrow function
function output_statistics(){
	let entries = Object.entries(statistics);
	if (entries.length == 0){
		return;
	}

	console.log(`--- usage statistics ${new Date()} of the last ${statistic_interval_ms / 1000 / 60} minutes ---`);

	let interval_s = statistic_interval_ms / 1000;

	for (let entry of entries){
		let ip = entry[0];
		let obj = entry[1];
		console.log(`${ip}:`);

		console.log(`  pdp connects ${obj.pdp_connects} avg ${obj.pdp_connects / interval_s}/s`);

		console.log(`  pdp tx ops ${obj.pdp_tx_ops} avg ${obj.pdp_tx_ops / interval_s}/s`);
		console.log(`  pdp tx ${obj.pdp_tx} bytes avg ${obj.pdp_tx / interval_s} bytes/s`);
		console.log(`  pdp rx ops ${obj.pdp_rx_ops} avg ${obj.pdp_rx_ops / interval_s}/s`);
		console.log(`  pdp rx ${obj.pdp_rx} bytes avg ${obj.pdp_rx / interval_s} bytes/s`);

		console.log(`  ptp connects ${obj.ptp_connects} avg ${obj.ptp_connects / interval_s}/s`);
		console.log(`  ptp listen connects ${obj.ptp_listen_connects} avg ${obj.ptp_listen_connects / interval_s}/s`);

		console.log(`  ptp tx ops ${obj.ptp_tx_ops} avg ${obj.ptp_tx_ops / interval_s}/s`);
		console.log(`  ptp tx ${obj.ptp_tx} bytes avg ${obj.ptp_tx / interval_s} bytes/s`);
		console.log(`  ptp rx ops ${obj.ptp_rx_ops} avg ${obj.ptp_rx_ops / interval_s}/s`);
		console.log(`  ptp rx ${obj.ptp_rx} bytes avg ${obj.ptp_rx / interval_s} bytes/s`);

		total_connects = obj.pdp_connects + obj.ptp_connects + obj.ptp_listen_connects;
		total_tx_ops = obj.pdp_tx_ops + obj.ptp_tx_ops;
		total_rx_ops = obj.pdp_rx_ops + obj.ptp_rx_ops;
		total_ops = total_tx_ops + total_rx_ops;
		total_tx = obj.pdp_tx + obj.ptp_tx;
		total_rx = obj.pdp_rx + obj.ptp_rx;
		total_data = total_tx + total_rx;

		console.log(`  total connects: ${total_connects} avg ${total_connects / interval_s}/s`);
		console.log(`  total tx ops: ${total_tx_ops} avg ${total_tx_ops / interval_s}/s`);
		console.log(`  total rx ops: ${total_rx_ops} avg ${total_rx_ops / interval_s}/s`);
		console.log(`  total ops: ${total_ops} avg ${total_ops / interval_s}/s`);
		console.log(`  total tx: ${total_tx} avg ${total_tx / interval_s} bytes/s`);
		console.log(`  total rx: ${total_rx} avg ${total_rx / interval_s} bytes/s`);
		console.log(`  total data: ${total_data} avg ${total_data / interval_s} bytes/s`);
	}
	statistics = {};
}

setInterval(output_statistics, statistic_interval_ms);

let pdp_tick = (ctx) => {
	let no_data = false;
	while(!no_data){
		switch(ctx.pdp_state){
			case "header":{
				if (ctx.pdp_data.length >= 14){
					let cur_data = ctx.pdp_data.slice(0, 14);
					ctx.pdp_data = ctx.pdp_data.slice(14);

					let addr = cur_data.slice(0, 8);
					let port = cur_data.slice(8, 10);
					let size = cur_data.slice(10, 14);

					// decode
					port = port.readUInt16LE();
					size = size.readUInt32LE();

					if (size >= 4096){
						log(`${ctx.session_name} ${get_sock_addr_str(ctx.socket)} is sending way too big data with size ${size}, ending session`);
						ctx.socket.destroy();
						delete sessions[ctx.session_name];
						return;
					}

					ctx.target_session_name = `PDP ${get_mac_str(addr)} ${port}`;
					ctx.pdp_data_size = size;

					ctx.pdp_state = "data";
				}else{
					no_data = true;
				}
				break;
			}
			case "data":{
				if (ctx.pdp_data.length >= ctx.pdp_data_size){
					let cur_data = ctx.pdp_data.slice(0, ctx.pdp_data_size);
					ctx.pdp_data = ctx.pdp_data.slice(ctx.pdp_data_size);

					let target_session = sessions[ctx.target_session_name];
					if (target_session != undefined){
						let addr = ctx.src_addr;
						let port = Buffer.alloc(2);
						let size = Buffer.alloc(4);
						port.writeUInt16LE(ctx.sport);
						size.writeUInt32LE(cur_data.length);

						target_session.socket.write(Buffer.concat([addr, port, size, cur_data]));
						track_bandwidth(target_session.ip, false, false, ctx.pdp_data_size);
					}
					track_bandwidth(ctx.ip, false, true, ctx.pdp_data_size);

					ctx.pdp_state = "header";
				}else{
					no_data = true;
				}
				break;
			}
			default:
				log(`bad state ${ctx.pdp_state} in pdp tick, debug this`);
				process.exit(1);
		}
	}
}

let close_ptp = (ctx) => {
	ctx.socket.destroy();
	delete sessions[ctx.session_name];
	if (ctx.peer_session != undefined){
		log(`bringing peer session ${ctx.peer_session.session_name} of ${get_sock_addr_str(ctx.peer_session.socket)} down as well`);
		ctx.peer_session.socket.destroy();
		delete sessions[ctx.peer_session.session_name];
	}
}

let ptp_tick = (ctx) => {
	let no_data = false;
	while(!no_data){
		switch(ctx.ptp_state){
			case "header":{
				if (ctx.ptp_data.length >= 4){
					let cur_data = ctx.ptp_data.slice(0, 4);
					ctx.ptp_data = ctx.ptp_data.slice(4);

					let size = cur_data.readUInt32LE();
					if (size > 50 * 1024 * 2){
						log(`${ctx.session_name} ${get_sock_addr_str(ctx.socket)} is sending way too big data with size ${size}, ending session`);
						close_ptp(ctx);
						return;
					}

					ctx.ptp_data_size = size;
					ctx.ptp_state = "data"
				}else{
					no_data = true;
				}
				break;
			}
			case "data":{
				if (ctx.ptp_data.length >= ctx.ptp_data_size){
					let cur_data = ctx.ptp_data.slice(0, ctx.ptp_data_size);
					ctx.ptp_data = ctx.ptp_data.slice(ctx.ptp_data_size);

					let size = Buffer.alloc(4);
					size.writeUInt32LE(ctx.ptp_data_size);

					ctx.peer_session.socket.write(Buffer.concat([size, cur_data]));
					track_bandwidth(ctx.peer_session.ip, true, false, ctx.ptp_data_size);
					track_bandwidth(ctx.ip, true, true, ctx.ptp_data_size);

					ctx.ptp_state = "header";
				}else{
					no_data = true;
				}
				break;
			}
			default:
				log(`bad state ${ctx.ptp_state} in ptp tick, debug this`);
				process.exit(1);
		}
	}
}

let remove_existing_and_insert_session = (ctx, name) => {
	let existing_session = sessions[name];
	if (existing_session != undefined){
		log(`dropping session ${existing_session.session_name} ${get_sock_addr_str(existing_session.socket)} for new session`);
		switch(existing_session.state){
			case "pdp":
			case "ptp_listen":{
				existing_session.socket.destroy();
				delete sessions[name];
				break;
			}
			case "ptp_connect":
			case "ptp_accept":{
				close_ptp(existing_session);
				break;
			}
			default:
				log(`bad state ${existing_session.state} in session replacement, debug this`);
				process.exit(1);
		}
	}

	sessions[name] = ctx;
}

let create_session = (ctx) => {
	let type = ctx.init_data.slice(0, 4);
	let src_addr = ctx.init_data.slice(4, 12);
	let sport = ctx.init_data.slice(12, 14);
	let dst_addr = ctx.init_data.slice(14, 22);
	let dport = ctx.init_data.slice(22, 24);

	// decode
	type = type.readInt32LE();
	sport = sport.readUInt16LE();
	dport = dport.readUInt16LE();

	ctx.src_addr = src_addr;
	ctx.sport = sport;
	ctx.dst_addr = dst_addr;
	ctx.dport = dport;

	ctx.src_addr_str = get_mac_str(ctx.src_addr);
	ctx.dst_addr_str = get_mac_str(ctx.dst_addr);

	delete ctx.init_data;

	switch(type){
		case AEMU_POSTOFFICE_INIT_PDP:{
			ctx.state = "pdp";
			ctx.session_name = `PDP ${get_mac_str(src_addr)} ${sport}`;
			ctx.pdp_data = ctx.outstanding_data;
			delete ctx.outstanding_data;
			ctx.pdp_state = "header";
			remove_existing_and_insert_session(ctx, ctx.session_name);
			log(`created session ${ctx.session_name} for ${get_sock_addr_str(ctx.socket)}`);
			track_connect(ctx.ip, false, false);
			pdp_tick(ctx);
			break;
		}
		case AEMU_POSTOFFICE_INIT_PTP_LISTEN:{
			ctx.state = "ptp_listen";
			ctx.session_name = `PTP_LISTEN ${get_mac_str(src_addr)} ${sport}`;
			delete ctx.outstanding_data;
			remove_existing_and_insert_session(ctx, ctx.session_name);
			log(`created session ${ctx.session_name} for ${get_sock_addr_str(ctx.socket)}`);
			track_connect(ctx.ip, true, true);
			break;
		}
		case AEMU_POSTOFFICE_INIT_PTP_CONNECT:{
			ctx.state = "ptp_connect";
			ctx.session_name = `PTP_CONNECT ${get_mac_str(src_addr)} ${sport} ${get_mac_str(dst_addr)} ${dport}`;

			let listen_session_name = `PTP_LISTEN ${get_mac_str(dst_addr)} ${dport}`;
			let listen_session = sessions[listen_session_name];
			if (listen_session == undefined){
				log(`not creating ${ctx.session_name} for ${get_sock_addr_str(ctx.socket)}, ${listen_session_name} not found`);
				ctx.socket.destroy();
				break;
			}

			remove_existing_and_insert_session(ctx, ctx.session_name);
			let port = Buffer.alloc(2);
			port.writeUInt16LE(sport);
			ctx.ptp_state = "waiting";
			ctx.ptp_data = ctx.outstanding_data;
			delete ctx.outstanding_data;
			listen_session.socket.write(Buffer.concat([src_addr, port]));
			log(`created session ${ctx.session_name} for ${get_sock_addr_str(ctx.socket)}`);
			track_connect(ctx.ip, true, false);

			setTimeout(() => {
				if (ctx.ptp_state == "waiting"){
					log(`the other side did not accept the connection request in 20 seconds, killing ${ctx.session_name} of ${get_sock_addr_str(ctx.socket)}`);
					ctx.socket.destroy();
					delete sessions[ctx.session_name];
				}
			}, 20000);
			break;
		}
		case AEMU_POSTOFFICE_INIT_PTP_ACCEPT:{
			ctx.state = "ptp_accept";
			ctx.session_name = `PTP_ACCEPT ${get_mac_str(src_addr)} ${sport} ${get_mac_str(dst_addr)} ${dport}`

			let connect_session_name = `PTP_CONNECT ${get_mac_str(dst_addr)} ${dport} ${get_mac_str(src_addr)} ${sport}`;
			let connect_session = sessions[connect_session_name];
			if (connect_session == undefined){
				log(`${connect_session_name} not found, closing ${ctx.session_name} of ${get_sock_addr_str(ctx.socket)}`);
				ctx.socket.destroy();
				break;
			}

			remove_existing_and_insert_session(ctx, ctx.session_name);
			ctx.peer_session = connect_session;
			connect_session.peer_session = ctx;
			ctx.ptp_state = "header";
			connect_session.ptp_state = "header";
			ctx.ptp_data = ctx.outstanding_data;
			delete ctx.outstanding_data;

			let port = Buffer.alloc(2);
			port.writeUInt16LE(sport);
			connect_session.socket.write(Buffer.concat([ctx.src_addr, port]));
			port.writeUInt16LE(dport);
			ctx.socket.write(Buffer.concat([ctx.dst_addr, port]));
			log(`created session ${ctx.session_name} for ${get_sock_addr_str(ctx.socket)}`);
			track_connect(ctx.ip, true, false);

			ptp_tick(ctx);
			ptp_tick(connect_session);
			break;
		}
		default:
			log(`${get_sock_addr_str(ctx.socket)} has bad init type ${type}, dropping connection`);
			ctx.socket.destroy();
	}
}

let on_connection = (socket) => {
	socket.setKeepAlive(true);
	socket.setNoDelay(true);

	let ctx = {
		socket:socket,
		init_data:Buffer.alloc(0),
		state:"init",
		ip:socket.remoteAddress
	};

	socket.on("error", (err) => {
		switch(ctx.state){
			case "init":
				log(`${get_sock_addr_str(ctx.socket)} errored during init, ${err}`);
				ctx.socket.destroy();
				break;
			case "pdp":
			case "ptp_listen":
				log(`${ctx.session_name} ${get_sock_addr_str(ctx.socket)} errored, ${err}`);
				ctx.socket.destroy();
				delete sessions[ctx.session_name];
				break;
			case "ptp_accept":
			case "ptp_connect":
				log(`${ctx.session_name} ${get_sock_addr_str(ctx.socket)} errored, ${err}`);
				close_ptp(ctx);
				break;
			default:
				log(`bad state ${ctx.state} on socket error, debug this`);
				process.exit(1);
		}
	})

	socket.on("end", () => {
		switch(ctx.state){
			case "init":
				log(`${get_sock_addr_str(ctx.socket)} closed during init`);
				ctx.socket.destroy();
				break;
			case "pdp":
			case "ptp_listen":
				log(`${ctx.session_name} ${get_sock_addr_str(ctx.socket)} closed by client`);
				ctx.socket.destroy();
				delete sessions[ctx.session_name];
				break;
			case "ptp_accept":
			case "ptp_connect":
				log(`${ctx.session_name} ${get_sock_addr_str(ctx.socket)} closed by client`);
				close_ptp(ctx);
				break;
			default:
				log(`bad state ${ctx.state} on socket end, debug this`);
				process.exit(1);
		}
	})

	socket.on("data", (new_data) => {
		switch(ctx.state){
			case "init":{
				let new_buffer = Buffer.concat([ctx.init_data, new_data]);
				
				if (new_buffer.length >= 24){
					ctx.init_data = new_buffer.slice(0, 24);
					ctx.outstanding_data = new_buffer.slice(24);
					create_session(ctx);
				}

				ctx.init_data = new_buffer;
				break;
			}
			case "pdp":{
				ctx.pdp_data = Buffer.concat([ctx.pdp_data, new_data]);
				pdp_tick(ctx);
				break;
			}
			case "ptp_listen":{
				// we just discard incoming data for ptp_listen
				break;
			}
			case "ptp_connect":
			case "ptp_accept":{
				ctx.ptp_data = Buffer.concat([ctx.ptp_data, new_data]);
				ptp_tick(ctx);
				break;
			}
			default:{
				log(`bad state ${ctx.state} on socket data handler, debug this`);
				process.exit(1);
			}
		}
	});

	setTimeout(() => {
		if (ctx.state == "init"){
			log(`removing stale connection ${get_sock_addr_str(ctx.socket)}`);
			ctx.socket.destroy();
		}
	}, 20000)
}

server.on("connection", on_connection);

log(`begin listening on port ${port}`);

server.listen({
	port:port,
	backlog:1000
});

let status_server = http.createServer();
status_server.on("error", (err) => {
	throw err;
});

status_server.on("request", (request, response) => {
	let ret = {};
	for (let entry of Object.entries(sessions)){
		let ctx = entry[1];
		ret_entry = {
			state:ctx.state,
			src_addr:ctx.src_addr_str,
			sport:ctx.sport
		};

		switch(ctx.state){
			case "pdp":
				ret_entry.pdp_state = ctx.pdp_state;
				break;
			case "ptp_listen":
				break;
			case "ptp_accept":
			case "ptp_connect":
				ret_entry.ptp_state = ctx.ptp_state;
				ret_entry.dst_addr = ctx.dst_addr_str;
				ret_entry.dport = ctx.dport;
				break;
			default:
				log(`bad state ${ctx.state} on status query, debug this`);
				process.exit(1);
		}

		if (ret[entry[1].src_addr_str] == undefined){
			ret[entry[1].src_addr_str] = [];
		}
		ret[entry[1].src_addr_str].push(ret_entry);
	}

	response.writeHead(200, {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"});
	response.end(JSON.stringify(ret));
});

log(`begin listening on port ${status_port} for server status`)

status_server.listen({
	port:status_port,
	backlog:1000
});
