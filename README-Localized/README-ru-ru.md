[![эмблема версии npm](https://img.shields.io/npm/v/@microsoft/microsoft-graph-types.svg)](https://www.npmjs.com/package/@microsoft/microsoft-graph-types)

# Типы TypeScript для Microsoft Graph
С помощью определений TypeScript для Microsoft Graph, редакторы могут использовать функции intellisense для объектов Microsoft Graph, включая пользователей, сообщения и группы.

## Установка

Рекомендуем включить файл .d.ts, загрузив его в [npm](https://www.npmjs.com/).

```bash

# Install types and save in package.json as a development dependency
npm install @microsoft/microsoft-graph-types --save-dev

```


![GIF функции intellisense и автоматическое заполнение сущностей Microsoft Graph в Visual Studio Code ](https://github.com/microsoftgraph/msgraph-typescript-typings/raw/master/typings-demo.gif)
## Примеры
В следующих примерах предполагается, что у вас есть действительный маркер доступа. Для выполнения запросов мы использовали [isomorphic-fetch](https://www.npmjs.com/package/isomorphic-fetch), но вы можете использоватькак нашу [клиентскую библиотеку JavaScript](https://github.com/microsoftgraph/msgraph-sdk-javascript), так и другую.
```typescript
import * as MicrosoftGraph from "@microsoft/microsoft-graph-types"

import * from 'isomorphic-fetch';
const accessToken:string = "";
```
### Список недавних сообщений
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
### Отправка сообщения пользователя, выполнившего вход
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
## Поддержка бета-версии Microsoft Graph
Если вы хотите протестировать конечные точки бета-версии Microsoft Graph, используйте эти типы одновременно с типами версии 1.0.

Обновите файл package.json, выполнив следующее:

```javascript
  "devDependencies": {
    // import published v1.0 types with a version from NPM
    "@microsoft/microsoft-graph-types": "^0.4.0",

    // import beta types from the beta branch on the GitHub repo
    "@microsoft/microsoft-graph-types-beta": "microsoftgraph/msgraph-typescript-typings#beta"
  }
}
```

Импортируйте бета типы из `@microsoft/microsoft-graph-types-beta`
```typescript
// import individual entities
import {User as BetaUser} from "@microsoft/microsoft-graph-types-beta"

// or import everything under MicrosoftGraphBeta
import * as MicrosoftGraphBeta from "@microsoft/microsoft-graph-types-beta"
```

## Поддерживаемые редакторы
Любой проект TypeScript может использовать эти типы с помощью TypeScript 2.0 или более поздней версии. Мы протестированы типы как зависимость в следующих редакторах.
* Visual Studio Code
* WebStorm
* Atom с плагином [atom-typescript](https://atom.io/packages/atom-typescript)

## Вопросы и комментарии

Мы будем рады получить от вас отзывы о проекте "Определения TypeScript". Вы можете отправлять нам вопросы и предложения в разделе [Проблемы](https://github.com/microsoftgraph/msgraph-typescript-typings/issues) этого репозитория.


## Помощь
См. [добавление рекомендаций](CONTRIBUTING.md).

## Дополнительные ресурсы

* [Microsoft Graph](https://graph.microsoft.io)
* [Центр разработчиков Office](http://dev.office.com/)
* [Клиентская библиотека JavaScript для Microsoft Graph](https://github.com/microsoftgraph/msgraph-sdk-javascript)

## Отчеты о безопасности

Если вы столкнулись с проблемами безопасности наших библиотек или служб, сообщите о проблеме по адресу [secure@microsoft.com](mailto:secure@microsoft.com), добавив как можно больше деталей. Возможно, вы получите вознаграждение, в рамках программы [Microsoft Bounty](http://aka.ms/bugbounty). Не публикуйте ошибки безопасности в ошибках GitHub или на любом общедоступном сайте. Вскоре после получения информации, мы свяжемся с вами. Рекомендуем вам настроить уведомления о нарушениях безопасности. Это можно сделать, подписавшись на уведомления безопасности консультационных служб на [этой странице](https://technet.microsoft.com/en-us/security/dd252948).

## Лицензия

© Корпорация Майкрософт. Все права защищены. Предоставляется по лицензии MIT ("Лицензия");

## В соответствии с "Правилами поведения разработчиков открытого кода Майкрософт".

Этот проект соответствует [Правилам поведения разработчиков открытого кода Майкрософт](https://opensource.microsoft.com/codeofconduct/). Дополнительные сведения см. в разделе [часто задаваемых вопросов о правилах поведения](https://opensource.microsoft.com/codeofconduct/faq/). Если у вас возникли вопросы или замечания, напишите нам по адресу [opencode@microsoft.com](mailto:opencode@microsoft.com).
