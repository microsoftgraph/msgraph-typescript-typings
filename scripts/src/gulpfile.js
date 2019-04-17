const { src, dest, series } = require("gulp");
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

exports.ReplaceVersion = series(ReplaceVersionInJson);
