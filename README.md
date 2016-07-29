# Microsoft Graph TypeScript Typings
The graph TypeScript definitions enables editors to provide intellisense on Graph objects.

There are a few different ways to use the Microsoft Graph definitions in your project.
* Directly reference microsoft-graph.d.ts with a triple slash reference at the top of your .ts files
```/// <reference path="microsoft-graph.d.ts" />```.
* Use a [tsconfig.json](http://www.typescriptlang.org/docs/handbook/tsconfig-json.html) file so the /// reference doesn't need to be in every .ts file. By default, all files (including .d.ts) will be included in the directly where tsconfig.json resides.

![Demo GIF](https://github.com/microsoftgraph/msgraph-typescript-typings/raw/master/typings-demo.gif)

## Note about date values
All DateTimeOffset values are returned as strings from the Microsoft Graph and should be wrapped in ```new Date()``` at runtime.
```typescript
let me:MicrosoftGraph.User = {}; // result from graph
let myBirthday = new Date(me.birthday);
console.log(myBirthday.toDateString());
```

## Questions and comments

We'd love to get your feedback about the TypeScript definitions project. You can send your questions and suggestions to us in the [Issues](https://github.com/microsoftgraph/msgraph-typescript-typings/issues) section of this repository.


## Contributing
You will need to sign a [Contributor License Agreement](https://cla.microsoft.com/) before submitting your pull request. To complete the Contributor License Agreement (CLA), you will need to submit a request via the form and then electronically sign the CLA when you receive the email containing the link to the document. 

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Additional resources

* [Microsoft Graph overview page](https://graph.microsoft.io)
* [Office Dev Center](http://dev.office.com/)

## Copyright
Copyright (c) 2016 Microsoft. All rights reserved.
