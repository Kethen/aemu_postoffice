const process = require("node:process");
const sqlite = require("node:sqlite");
const fs = require("node:fs");

if (process.argv.length < 4){
	console.log(`usage ${process.argv[0]} ${process.argv[1]} <sql adhocctl database file> <output json>`)
	process.exit(1);
}

const input_path = process.argv[2];
const output_path = process.argv[3];

let db = new sqlite.DatabaseSync(input_path);
let names = db.prepare('SELECT * FROM productids').iterate();
let crosslinks = db.prepare('SELECT * FROM crosslinks').iterate();

let out = {
	"names":{},
	"crosslinks":{}
};

names.forEach((element) => {
	out.names[element.id] = element.name;
});
crosslinks.forEach((element) => {
	out.crosslinks[element.id_from] = element.id_to;
});

for (const [key, value] of Object.entries(out.crosslinks)){
	let recursive_entry = out.crosslinks[value];
	if (recursive_entry != undefined){
		console.log(`recursive crosslink detected, ${key} -> ${value} -> ${recursive_entry} -> ..., please fix this on the json output before usage`);
	}
}

const output_string = JSON.stringify(out, null, 4);

fs.writeFile(output_path, output_string, (err) => {
	if (err){
		throw err;
	}
	console.log(`file saved to ${output_path}`);
});
