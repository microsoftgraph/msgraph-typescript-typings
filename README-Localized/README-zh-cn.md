[![npm 版本徽章](https://img.shields.io/npm/v/@microsoft/microsoft-graph-types.svg)](https://www.npmjs.com/package/@microsoft/microsoft-graph-types)

# Microsoft Graph TypeScript 类型
Microsoft Graph TypeScript 定义使编辑器可以提供有关 Microsoft Graph 对象（包括用户、邮件和组）的智能感知。

## 安装

建议通过 [npm](https://www.npmjs.com/) 下载此包以便包含 .d.ts 文件。

```bash

# Install types and save in package.json as a development dependency
npm install @microsoft/microsoft-graph-types --save-dev

```


![此 GIF 显示了 Visual Studio Code 中的 Microsoft Graph 实体的智能感知和自动完成](https://github.com/microsoftgraph/msgraph-typescript-typings/raw/master/typings-demo.gif)
## 示例
以下示例假定你拥有有效的访问令牌。我们使用了 [isomorphic-fetch](https://www.npmjs.com/package/isomorphic-fetch) 执行请求，但你也可以使用[我们的 JavaScript 客户端库](https://github.com/microsoftgraph/msgraph-sdk-javascript)或其他库。
```typescript
import * as MicrosoftGraph from "@microsoft/microsoft-graph-types"

import * from 'isomorphic-fetch';
const accessToken:string = "";
```
### 列出最近的邮件
```typescript
let url = "https://graph.microsoft.com/v1.0/me/messages";
let request = new Request(url, {
    method: "GET",
    headers: new Headers({
        "Authorization": "Bearer " + accessToken
    })
});

fetch(request)
.then((response) => {
    response.json().then((res) => {
        let messages:[MicrosoftGraph.Message] = res.value;
        for (let msg of messages) { //iterate through the recent messages
            console.log(msg.subject);
            console.log(msg.toRecipients[0].emailAddress.address);
        }
    });

})
.catch((error) => {
    console.error(error);
});
```
### 使用已登录用户的身份发送电子邮件
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
let url = "https://graph.microsoft.com/v1.0/users/me/sendMail";
let request = new Request(
            url, {
                method: "POST",
                body: JSON.stringify({
                    message: mail
                }),
                headers: new Headers({
                    "Authorization": "Bearer " + accessToken,
                    'Content-Type': 'application/json'
                })
            }
        );
        
fetch(request)
.then((response) => {
    if(response.ok === true) {
        console.log("Mail sent successfully..!!");
    }
})
.catch((err) => {
    console.error(err);
});

```
## Microsoft Graph 测试版支持
如果要测试 Microsoft Graph 测试版终结点，可将这些类型与 v1.0 类型同时使用。

使用以下内容更新你的 package.json 文件：

```javascript
  "devDependencies": {
    // import published v1.0 types with a version from NPM
    "@microsoft/microsoft-graph-types": "^0.4.0",

    // import beta types from the beta branch on the GitHub repo
    "@microsoft/microsoft-graph-types-beta": "microsoftgraph/msgraph-typescript-typings#beta"
  }
}
```

从 `@microsoft/microsoft-graph-types-beta` 导入测试版类型
```typescript
// import individual entities
import {User as BetaUser} from "@microsoft/microsoft-graph-types-beta"

// or import everything under MicrosoftGraphBeta
import * as MicrosoftGraphBeta from "@microsoft/microsoft-graph-types-beta"
```

## 支持的编辑器
当至少使用 TypeScript 2.0 时，任何 TypeScript 项目都可以使用这些类型。我们已测试在以下编辑器中包含这些类型作为依赖项。
* Visual Studio Code
* WebStorm
* 带有 [atom-typescript](https://atom.io/packages/atom-typescript) 插件的 Atom

## 问题和意见

我们非常乐意倾听你对于 TypeScript 定义项目的反馈。你可通过该存储库中的[问题](https://github.com/microsoftgraph/msgraph-typescript-typings/issues)部分向我们发送问题和建议。


## 参与
请参阅[参与指南](CONTRIBUTING.md)。

## 其他资源

* [Microsoft Graph](https://graph.microsoft.io)
* [Office 开发人员中心](http://dev.office.com/)
* [Microsoft Graph JavaScript 客户端库](https://github.com/microsoftgraph/msgraph-sdk-javascript)

## 安全报告

如果发现库或服务存在安全问题，请尽可能详细地报告至 [secure@microsoft.com](mailto:secure@microsoft.com)。提交可能有资格通过 [Microsoft 报告奖励](http://aka.ms/bugbounty)计划获得奖励。请勿发布安全问题至 GitHub 问题或其他任何公共网站。我们将在收到信息后立即与你联系。建议发生安全事件时获取相关通知，方法是访问[此页](https://technet.microsoft.com/en-us/security/dd252948)并订阅“安全公告通知”。

## 许可证

版权所有 (c) Microsoft Corporation。保留所有权利。根据 MIT 许可证（简称“许可证”）获得许可。

## 我们重视并遵守“Microsoft 开放源代码行为准则”

此项目已采用 [Microsoft 开放源代码行为准则](https://opensource.microsoft.com/codeofconduct/)。有关详细信息，请参阅[行为准则常见问题解答](https://opensource.microsoft.com/codeofconduct/faq/)。如有其他任何问题或意见，也可联系 [opencode@microsoft.com](mailto:opencode@microsoft.com)。
