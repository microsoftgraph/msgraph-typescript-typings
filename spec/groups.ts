import {assert} from 'chai'

import { getClient, randomString } from "./testHelpers"
import {Group} from '../microsoft-graph'

declare const describe, it;

describe('Group entity tests', function() {
  this.timeout(10*1000);
  it('should have values for basic properties that match type definitions', function() {
    return getClient().api("https://graph.microsoft.com/v1.0/groups/").get().then((json) => {
        const group = json as Group;
        assert.isNotNull(group.displayName);
        assert.isNotNull(group.mail);
        assert.isNotNull(group.id);

        assert.isUndefined(group['invalidPropertyName']);
        return Promise.resolve();
      });
  });

  it('should create a group and validate entity properties were set', function() {
    const group:Group = {
        displayName: "Sample test group",
        description: randomString(),
        groupTypes: [
            "Unified"
        ],
        mailEnabled: true,
        mailNickname: "Group911e5",
        securityEnabled: true
    };

    return getClient().api("https://graph.microsoft.com/v1.0/groups/").post(group).then((groupResponse) => {
        let createdGroup = groupResponse as Group;
        assert.equal(createdGroup.displayName, group.displayName);
        assert.equal(createdGroup.description, group.description);
        assert.equal(createdGroup.mailEnabled, group.mailEnabled);
        assert.isString(createdGroup.id);
        return Promise.resolve();
    });
  });
});