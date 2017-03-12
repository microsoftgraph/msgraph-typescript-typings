import {assert} from 'chai'

import { getClient, randomString } from "./testHelpers"
import {User} from '../microsoft-graph'

declare const describe, it;

describe('User entity tests', function() {
  this.timeout(10*1000);
  it('should have values for basic properties that match type definitions', function() {
    return getClient().api("https://graph.microsoft.com/v1.0/me/").get().then((res) => {
        const user = res as User;
        assert.isNotNull(user.displayName);
        assert.isNotNull(user.mail);
        assert.isNotNull(user.id);
        
        assert.isNotNull(user.surname);
        assert.isNotNull(user.userPrincipalName);
        
        assert.isArray(user.businessPhones);

        assert.isUndefined(user['invalidPropertyName']);
      });
  });

  it('should be able to modify officeLocation property value', function() {
    const officeLocation = randomString();

    return getClient().api("https://graph.microsoft.com/v1.0/me/").patch({officeLocation}).then(() => {
      return getClient().api("https://graph.microsoft.com/v1.0/me/").get().then((res) => {
        const user = res as User;
        assert.equal(user.officeLocation, officeLocation);
        return Promise.resolve();
      });
    });
  });


  it('should be able to modify givenName property value', function() {
    const givenName = randomString();

    return getClient().api("https://graph.microsoft.com/v1.0/me/").patch({givenName}).then(() => {
      return getClient().api("https://graph.microsoft.com/v1.0/me/").get().then((res) => {
        const user = res as User;
        assert.equal(user.givenName, givenName);
        return Promise.resolve();
      });
    });
  });

  it('[collection] types should match user entity returned in collection', function() {
    return getClient().api("https://graph.microsoft.com/v1.0/users/").get().then((collection) => {
      const users:User[] = collection.value;
      assert.isNotNull(users[0].displayName);
      assert.isNotNull(users[0].id);
      assert.isNotNull(users[0].mail);
    });
  })
});