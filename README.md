[![npm version badge](https://img.shields.io/npm/v/@microsoft/microsoft-graph-types.svg)](https://www.npmjs.com/package/@microsoft/microsoft-graph-types)

# Microsoft Graph TypeScript Types
The Microsoft Graph TypeScript definitions enable editors to provide intellisense on Microsoft Graph objects including users, messages, and groups.

## Installation

We recommend including the .d.ts file by downloading this package through [npm](https://www.npmjs.com/).

```bash

# Install types and save in package.json as a development dependency
npm install @microsoft/microsoft-graph-types --save-dev

```


![GIF showing intellisense and autocompletion for Microsoft Graph entities in Visual Studio Code ](https://github.com/microsoftgraph/msgraph-typescript-typings/raw/master/typings-demo.gif)
## Examples
The following examples assume that you have a valid access token. We used [superagent](https://github.com/visionmedia/superagent) to perform the HTTP requests, but you can use [our JavaScript client library](https://github.com/microsoftgraph/msgraph-sdk-javascript) or other libraries as well.
```typescript
import * as MicrosoftGraph from "@microsoft/microsoft-graph-types"

import * as request from 'superagent';
const accessToken:string = "";
```
### List my recent messages
```typescript
request
    .get("https://graph.microsoft.com/v1.0/me/messages")
    .set('Authorization', 'Bearer ' + accessToken)
    .end((err, res) => {
        if (err) {
            console.error(err)
            return;
        }
        let messages:[MicrosoftGraph.Message] = res.body.value;
        for (let msg of messages) { //iterate through the recent messages
            console.log(msg.subject);
            console.log(msg.toRecipients[0].emailAddress.address);
        }

    })
```
### Send an email as the logged in user
```typescript
// Create the message object

// Note that all the properties must follow the interface definitions.
// For example, this will not compile if you try to type "xml" instead of "html" for contentType. 

let mail:MicrosoftGraph.Message = {
    subject: "Microsoft Graph TypeScript Sample",
    toRecipients: [{
        emailAddress: {
            address: "microsoftgraph@example.com"
        }
    }],
    body: {
        content: "<h1>Microsoft Graph TypeScript Sample</h1>Try modifying the sample",
        contentType: "html"
    }
}
// send the email by sending a POST request to the Microsoft Graph
request
    .post('https://graph.microsoft.com/v1.0/users/me/sendMail')
    .send({message: mail})
    .set('Authorization', 'Bearer ' + accessToken)
    .end((err, res) => {
        if (err) {
            console.error(err)
            return;
        }
        console.log(res)
    })

```
## Supported editors
Any TypeScript project can consume these types when using at least TypeScript 2.0.  We've tested including the types as a dependency in the following editors.
* Visual Studio Code
* WebStorm
* Atom with the [atom-typescript](https://atom.io/packages/atom-typescript) plugin

## Note about date values
All DateTimeOffset values are returned as strings from Microsoft Graph and should be wrapped in ```new Date()``` at runtime.
```typescript
let me:MicrosoftGraph.User = {}; // result from graph
let myBirthday = new Date(me.birthday);
console.log(myBirthday.toDateString());
```

## Questions and comments

We'd love to get your feedback about the TypeScript definitions project. You can send your questions and suggestions to us in the [Issues](https://github.com/microsoftgraph/msgraph-typescript-typings/issues) section of this repository.


## Contributing
Please see the [contributing guidelines](CONTRIBUTING.md).

## Additional resources

* [Microsoft Graph](https://graph.microsoft.io)
* [Office Dev Center](http://dev.office.com/)
* [Microsoft Graph JavaScript Client Library](https://github.com/microsoftgraph/msgraph-sdk-javascript)

## Copyright
Copyright (c) 2017 Microsoft. All rights reserved.
