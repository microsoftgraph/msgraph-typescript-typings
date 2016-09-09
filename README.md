# Microsoft Graph TypeScript Typings
The Microsoft Graph TypeScript definitions enable editors to provide intellisense on Microsoft Graph objects.

You can use Microsoft Graph definitions in your project in a few ways:
* Directly reference microsoft-graph.d.ts with a triple slash reference at the top of your .ts files.
```/// <reference path="microsoft-graph.d.ts" />```.
* Use a [tsconfig.json](http://www.typescriptlang.org/docs/handbook/tsconfig-json.html) file so the /// reference doesn't need to be in every .ts file. By default, all files (including .d.ts) will be included in the directly where tsconfig.json resides.

![Demo GIF](https://github.com/microsoftgraph/msgraph-typescript-typings/raw/master/typings-demo.gif)
## Examples
The following examples assume that you have a valid access token. We used [superagent](https://github.com/visionmedia/superagent) to perform the HTTP requests, but you can use [our JavaScript SDK](https://github.com/microsoftgraph/msgraph-sdk-javascript) or other libraries as well.
```typescript
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
* [Microsoft Graph JavaScript SDK](https://github.com/microsoftgraph/msgraph-sdk-javascript)

## Copyright
Copyright (c) 2016 Microsoft. All rights reserved.
