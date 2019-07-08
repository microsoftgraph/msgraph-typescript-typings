const { src, dest, series } = require("gulp");
const replace = require("gulp-replace");
const jsonModify = require("gulp-json-modify");
const argv = require("yargs").argv;

function ReplaceVersionInJson () {
    const versionKey = "version";
    return src(["../../package.json", "../../package-lock.json"])
            .pipe(jsonModify({
                key: versionKey,
                value: argv.newVersion
            }))
            .pipe(dest("../../"));
}

function ReplaceVersionInVersionFile() {
	let DTVersionArr = argv.newVersion.split(".");
	DTVersionArr.splice(2);
	return src(["../../microsoft-graph.d.ts"])
		.pipe(replace(/Type definitions for non-npm package microsoft-graph .+/g, `Type definitions for non-npm package microsoft-graph ${DTVersionArr.join(".")}`))
		.pipe(dest("../../"));
}

exports.ReplaceVersion = series(ReplaceVersionInJson, ReplaceVersionInVersionFile);
