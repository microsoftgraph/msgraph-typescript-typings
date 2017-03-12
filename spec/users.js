"use strict";
const chai_1 = require("chai");
const testHelpers_1 = require("./testHelpers");
describe('User entity tests', function () {
    this.timeout(10 * 1000);
    it('should have values for basic properties that match type definitions', function () {
        return testHelpers_1.getClient().api("https://graph.microsoft.com/v1.0/me/").get().then((res) => {
            const user = res;
            chai_1.assert.isNotNull(user.displayName);
            chai_1.assert.isNotNull(user.mail);
            chai_1.assert.isNotNull(user.id);
            chai_1.assert.isNotNull(user.surname);
            chai_1.assert.isNotNull(user.userPrincipalName);
            chai_1.assert.isArray(user.businessPhones);
            chai_1.assert.isUndefined(user['invalidPropertyName']);
        });
    });
    it('should be able to modify officeLocation property value', function () {
        const officeLocation = testHelpers_1.randomString();
        return testHelpers_1.getClient().api("https://graph.microsoft.com/v1.0/me/").patch({ officeLocation }).then(() => {
            return testHelpers_1.getClient().api("https://graph.microsoft.com/v1.0/me/").get().then((res) => {
                const user = res;
                chai_1.assert.equal(user.officeLocation, officeLocation);
                return Promise.resolve();
            });
        });
    });
    it('should be able to modify givenName property value', function () {
        const givenName = testHelpers_1.randomString();
        return testHelpers_1.getClient().api("https://graph.microsoft.com/v1.0/me/").patch({ givenName }).then(() => {
            return testHelpers_1.getClient().api("https://graph.microsoft.com/v1.0/me/").get().then((res) => {
                const user = res;
                chai_1.assert.equal(user.givenName, givenName);
                return Promise.resolve();
            });
        });
    });
    it('[collection] types should match user entity returned in collection', function () {
        return testHelpers_1.getClient().api("https://graph.microsoft.com/v1.0/users/").get().then((collection) => {
            const users = collection.value;
            chai_1.assert.isNotNull(users[0].displayName);
            chai_1.assert.isNotNull(users[0].id);
            chai_1.assert.isNotNull(users[0].mail);
        });
    });
});
//# sourceMappingURL=users.js.map