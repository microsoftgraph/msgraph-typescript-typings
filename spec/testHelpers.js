"use strict";
const secrets_1 = require("./secrets");
const microsoft_graph_client_1 = require("@microsoft/microsoft-graph-client");
function getClient() {
    return microsoft_graph_client_1.Client.init({
        authProvider: (done) => {
            done(null, secrets_1.AccessToken);
        }
    });
}
exports.getClient = getClient;
function randomString() {
    return Math.random().toString(36).substring(7);
}
exports.randomString = randomString;
//# sourceMappingURL=testHelpers.js.map