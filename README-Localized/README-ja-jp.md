[![npm バージョン バッジ](https://img.shields.io/npm/v/@microsoft/microsoft-graph-types.svg)](https://www.npmjs.com/package/@microsoft/microsoft-graph-types)

# Microsoft Graph TypeScript 型
Microsoft Graph TypeScript 定義により、編集者は、ユーザー、メッセージ、グループを含む Microsoft Graph オブジェクトに Intellisense を提供できます。

## インストール

このパッケージを [npm](https://www.npmjs.com/)からダウンロードして、.d.ts ファイルを含めることをお勧めします。

```bash

# Install types and save in package.json as a development dependency
npm install @microsoft/microsoft-graph-types --save-dev

```


![Visual Studio Code の Intellisense を表示する GIF と Microsoft Graph エンティティのオートコンプリーション](https://github.com/microsoftgraph/msgraph-typescript-typings/raw/master/typings-demo.gif)
## 例
次の例では、有効なアクセス トークンがあることを前提としています。要求を実行するために [isomorphic-fetch](https://www.npmjs.com/package/isomorphic-fetch) を使用していましたが、[当社の JavaScript クライアント ライブラリ](https://github.com/microsoftgraph/msgraph-sdk-javascript)または他のライブラリを使用することもできます。
```typescript
import * as MicrosoftGraph from "@microsoft/microsoft-graph-types"

import * from 'isomorphic-fetch';
const accessToken:string = "";
```
### 最近使用したメッセージを一覧表示する
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
### ログインしているユーザーとしてメールを送信する
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
## Microsoft Graph ベータ版をサポート
Microsoft Graph ベータ版のエンドポイントをテストする場合は、これらの型を v1.0 の型と同時に使用できます。

package.json ファイルを次のように更新します。

```javascript
  "devDependencies": {
    // import published v1.0 types with a version from NPM
    "@microsoft/microsoft-graph-types": "^0.4.0",

    // import beta types from the beta branch on the GitHub repo
    "@microsoft/microsoft-graph-types-beta": "microsoftgraph/msgraph-typescript-typings#beta"
  }
}
```

`@microsoft/microsoft-graph-types-beta` からベータ タイプをインポートする
```typescript
// import individual entities
import {User as BetaUser} from "@microsoft/microsoft-graph-types-beta"

// or import everything under MicrosoftGraphBeta
import * as MicrosoftGraphBeta from "@microsoft/microsoft-graph-types-beta"
```

## サポートされるエディター
少なくとも TypeScript 2.0 を使用している場合、TypeScript プロジェクトはこれらの型を使用できます。次のエディターで依存関係として型を含めることをテストしました。
* Visual Studio Code
* WebStorm
* [atom-typescript](https://atom.io/packages/atom-typescript) プラグインを使用する Atom

## 質問とコメント

TypeScript 定義プロジェクトに関するフィードバックをお寄せください。質問や提案につきましては、このリポジトリの「[問題](https://github.com/microsoftgraph/msgraph-typescript-typings/issues)」セクションで送信できます。


## 投稿
[投稿ガイドライン](CONTRIBUTING.md)を参照してください。

## その他のリソース

* [Microsoft Graph](https://graph.microsoft.io)
* [Office デベロッパー センター](http://dev.office.com/)
* [Microsoft Graph JavaScript クライアント ライブラリ](https://github.com/microsoftgraph/msgraph-sdk-javascript)

## セキュリティ レポート

ライブラリまたはサービスでセキュリティに関する問題を発見した場合は、できるだけ詳細に [secure@microsoft.com](mailto:secure@microsoft.com) に報告してください。提出物は、[Microsoft Bounty](http://aka.ms/bugbounty) プログラムを通じて報酬を受ける対象となる場合があります。セキュリティの問題を GitHub の問題や他のパブリック サイトに投稿しないでください。情報を受け取り次第、ご連絡させていただきます。セキュリティの問題が発生したときに通知を受け取ることをお勧めします。そのためには、[このページ](https://technet.microsoft.com/en-us/security/dd252948)にアクセスし、セキュリティ アドバイザリ通知を受信登録してください。

## ライセンス

Copyright (c) Microsoft Corporation。All rights reserved.MIT ライセンス ("ライセンス") に基づいてライセンスされています。

## Microsoft Open Source Code of Conduct (Microsoft オープン ソース倫理規定) を尊重し、遵守します

このプロジェクトでは、[Microsoft Open Source Code of Conduct (Microsoft オープン ソース倫理規定)](https://opensource.microsoft.com/codeofconduct/) が採用されています。詳細については、「[Code of Conduct の FAQ (倫理規定の FAQ)](https://opensource.microsoft.com/codeofconduct/faq/)」を参照してください。また、その他の質問やコメントがあれば、[opencode@microsoft.com](mailto:opencode@microsoft.com) までお問い合わせください。
