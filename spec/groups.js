"use strict";
const chai_1 = require("chai");
const testHelpers_1 = require("./testHelpers");
describe('Group entity tests', function () {
    this.timeout(10 * 1000);
    it('should have values for basic properties that match type definitions', function () {
        return testHelpers_1.getClient().api("https://graph.microsoft.com/v1.0/groups/").get().then((json) => {
            const group = json;
            chai_1.assert.isNotNull(group.displayName);
            chai_1.assert.isNotNull(group.mail);
            chai_1.assert.isNotNull(group.id);
            chai_1.assert.isUndefined(group['invalidPropertyName']);
            return Promise.resolve();
        });
    });
    it('should create a group and validate entity properties were set', function () {
        const group = {
            displayName: "Sample test group",
            description: testHelpers_1.randomString(),
            groupTypes: [
                "Unified"
            ],
            mailEnabled: true,
            mailNickname: "Group911e5",
            securityEnabled: true
        };
        return testHelpers_1.getClient().api("https://graph.microsoft.com/v1.0/groups/").post(group).then((groupResponse) => {
            let createdGroup = groupResponse;
            chai_1.assert.equal(createdGroup.displayName, group.displayName);
            chai_1.assert.equal(createdGroup.description, group.description);
            chai_1.assert.equal(createdGroup.mailEnabled, group.mailEnabled + "1");
            chai_1.assert.isString(createdGroup.id);
            return Promise.resolve();
        });
    });
});
//# sourceMappingURL=groups.js.map