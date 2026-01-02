const net = require('node:net');
const port = 27313

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
						ctx.socket.end();
						delete sessions[ctx.session_name];
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
					}

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
	ctx.socket.end();
	delete sessions[ctx.session_name];
	if (ctx.peer_session != undefined){
		log(`bringing peer session ${ctx.peer_session.session_name} of ${get_sock_addr_str(ctx.peer_session.socket)} down as well`);
		ctx.peer_session.socket.end();
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

	switch(type){
		case AEMU_POSTOFFICE_INIT_PDP:{
			ctx.state = "pdp";
			ctx.session_name = `PDP ${get_mac_str(src_addr)} ${sport}`;
			ctx.pdp_data = ctx.outstanding_data;
			ctx.pdp_state = "header";
			sessions[ctx.session_name] = ctx;
			log(`created session ${ctx.session_name} for ${get_sock_addr_str(ctx.socket)}`);
			pdp_tick(ctx);
			break;
		}
		case AEMU_POSTOFFICE_INIT_PTP_LISTEN:{
			ctx.state = "ptp_listen";
			ctx.session_name = `PTP_LISTEN ${get_mac_str(src_addr)} ${sport}`;
			sessions[ctx.session_name] = ctx;
			log(`created session ${ctx.session_name} for ${get_sock_addr_str(ctx.socket)}`);
			break;
		}
		case AEMU_POSTOFFICE_INIT_PTP_CONNECT:{
			ctx.state = "ptp_connect";
			ctx.session_name = `PTP_CONNECT ${get_mac_str(src_addr)} ${sport} ${get_mac_str(dst_addr)} ${dport}`;

			let listen_session_name = `PTP_LISTEN ${get_mac_str(dst_addr)} ${dport}`;
			let listen_session = sessions[listen_session_name];
			if (listen_session == undefined){
				log(`not creating ${ctx.session_name} for ${get_sock_addr_str(ctx.socket)}, ${listen_session_name} not found`);
				ctx.socket.end();
				break;
			}

			sessions[ctx.session_name] = ctx;
			let port = Buffer.alloc(2);
			port.writeUInt16LE(sport);
			ctx.ptp_state = "waiting";
			ctx.ptp_data = ctx.outstanding_data;
			listen_session.socket.write(Buffer.concat([src_addr, port]));
			log(`created session ${ctx.session_name} for ${get_sock_addr_str(ctx.socket)}`);
			setTimeout(() => {
				if (ctx.ptp_state == "waiting"){
					log(`the other side did not accept the connection request in 20 seconds, killing ${ctx.session_name} of ${get_sock_addr_str(ctx.socket)}`);
					ctx.socket.end();
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
				ctx.socket.end();
				delete sessions[ctx.session_name];
			}

			sessions[ctx.session_name] = ctx;
			ctx.peer_session = connect_session;
			connect_session.peer_session = ctx;
			ctx.ptp_state = "header";
			connect_session.ptp_state = "header";
			ctx.ptp_data = ctx.outstanding_data;

			let port = Buffer.alloc(2);
			port.writeUInt16LE(sport);
			connect_session.socket.write(Buffer.concat([ctx.src_addr, port]));
			port.writeUInt16LE(dport);
			ctx.socket.write(Buffer.concat([ctx.dst_addr, port]));

			ptp_tick(ctx);
			ptp_tick(connect_session);
			break;
		}
		default:
			log(`${get_sock_addr_str(ctx.socket)} has bad init type ${type}, dropping connection`);
			ctx.socket.end();
	}
}

let on_connection = (socket) => {
	socket.setKeepAlive(true);
	socket.setNoDelay(true);

	let ctx = {
		socket:socket,
		init_data:Buffer.alloc(0),
		state:"init"
	};

	socket.on("error", (err) => {
		switch(ctx.state){
			case "init":
				log(`${get_sock_addr_str(ctx.socket)} errored during init, ${err}`);
				ctx.socket.end();
				break;
			case "pdp":
				log(`${ctx.session_name} ${get_sock_addr_str(ctx.socket)} errored, ${err}`);
				ctx.socket.end();
				break;
			case "ptp_listen":
				log(`${ctx.session_name} ${get_sock_addr_str(ctx.socket)} errored, ${err}`);
				ctx.socket.end();
				break;
			case "ptp_accept":
			case "ptp_connect":
				log(`${ctx.session_name} ${get_sock_addr_str(ctx.socket)} errored, ${err}`);
				close_ptp(ctx);
				break;
			default:
				log(`bad state ${ctx.state} on end, debug this`);
				process.exit(1);
		}
	})

	socket.on("end", () => {
		switch(ctx.state){
			case "init":
				log(`${get_sock_addr_str(ctx.socket)} closed during init`);
				ctx.socket.end();
				break;
			case "pdp":
				log(`${ctx.session_name} ${get_sock_addr_str(ctx.socket)} closed by client`);
				ctx.socket.end();
				break;
			case "ptp_listen":
				log(`${ctx.session_name} ${get_sock_addr_str(ctx.socket)} closed by client`);
				ctx.socket.end();
				break;				
			case "ptp_accept":
			case "ptp_connect":
				log(`${ctx.session_name} ${get_sock_addr_str(ctx.socket)} closed by client`);
				close_ptp(ctx);
				break;
			default:
				log(`bad state ${ctx.state} on end, debug this`);
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
}

server.on("connection", on_connection);

log(`begin listening on port ${port}`);

server.listen({
	port:port,
	backlog:1000
});
