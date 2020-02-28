[![selo de versão do npm](https://img.shields.io/npm/v/@microsoft/microsoft-graph-types.svg)](https://www.npmjs.com/package/@microsoft/microsoft-graph-types)

# Tipos de TypeScript do Microsoft Graph
As definições de TypeScript do Microsoft Graph permitem que os editores forneçam o IntelliSense em objetos do Microsoft Graph, incluindo usuários, mensagens e grupos.

## Instalação

Recomendamos incluir o arquivo .d.ts baixando esse pacote pelo [npm](https://www.npmjs.com/).

```bash

# Install types and save in package.json as a development dependency
npm install @microsoft/microsoft-graph-types --save-dev

```


![GIF que mostra o IntelliSense e o preenchimento automático para entidades do Microsoft Graph no Visual Studio Code](https://github.com/microsoftgraph/msgraph-typescript-typings/raw/master/typings-demo.gif)
## Exemplos
Os exemplos a seguir supõem que você tenha um token de acesso válido. Usamos [isomorphic-fetch](https://www.npmjs.com/package/isomorphic-fetch) para executar solicitações, mas você também pode usar [nossa biblioteca de cliente de JavaScript](https://github.com/microsoftgraph/msgraph-sdk-javascript) ou outras bibliotecas.
```typescript
import * as MicrosoftGraph from "@microsoft/microsoft-graph-types"

import * from 'isomorphic-fetch';
const accessToken:string = "";
```
### Lista minhas mensagens recentes
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
### Envia um email como o usuário conectado
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
## Suporte ao Microsoft Graph beta
Se você quer testar os pontos de extremidade do Microsoft Graph beta, é possível usá-los simultaneamente com os tipos v 1.0.

Atualize o arquivo package.json com o seguinte:

```javascript
  "devDependencies": {
    // import published v1.0 types with a version from NPM
    "@microsoft/microsoft-graph-types": "^0.4.0",

    // import beta types from the beta branch on the GitHub repo
    "@microsoft/microsoft-graph-types-beta": "microsoftgraph/msgraph-typescript-typings#beta"
  }
}
```

Importe os tipos beta de `@microsoft/microsoft-graph-types-beta`
```typescript
// import individual entities
import {User as BetaUser} from "@microsoft/microsoft-graph-types-beta"

// or import everything under MicrosoftGraphBeta
import * as MicrosoftGraphBeta from "@microsoft/microsoft-graph-types-beta"
```

## Editores compatíveis
Todos os projetos TypeScript podem consumir esses tipos ao usar pelo menos o TypeScript 2.0. Testamos e incluímos os tipos como uma dependência nos editores a seguir.
* Visual Studio Code
* WebStorm
* Atom with the [atom-typescript](https://atom.io/packages/atom-typescript) plugin

## Perguntas e comentários

Gostaríamos de saber sua opinião sobre o projeto de definições de TypeScript. Você pode enviar perguntas e sugestões na seção [Problemas](https://github.com/microsoftgraph/msgraph-typescript-typings/issues) deste repositório.


## Colaboração
Confira as [diretrizes de colaboração](CONTRIBUTING.md).

## Recursos adicionais

* [Microsoft Graph](https://graph.microsoft.io)
* [Centro de Desenvolvimento do Office](http://dev.office.com/)
* [Biblioteca de cliente de JavaScript do Microsoft Graph](https://github.com/microsoftgraph/msgraph-sdk-javascript)

## Relatórios de segurança

Se você encontrar um problema de segurança com nossas bibliotecas ou serviços, informe-o em [secure@microsoft.com](mailto:secure@microsoft.com) com o máximo de detalhes possível. O seu envio pode estar qualificado para uma recompensa por meio do programa [Microsoft Bounty](http://aka.ms/bugbounty). Não poste problemas de segurança nos Problemas do GitHub ou qualquer outro site público. Entraremos em contato com você em breve após receber as informações. Recomendamos que você obtenha notificações sobre a ocorrência de incidentes de segurança visitando [esta página](https://technet.microsoft.com/en-us/security/dd252948) e assinando os alertas do Security Advisory.

## Licença

Copyright (c) Microsoft Corporation. Todos os direitos reservados. Licenciada sob a Licença do MIT (a "Licença");

## Valorizamos e cumprimos o Código de Conduta de Código Aberto da Microsoft

Este projeto adotou o [Código de Conduta de Código Aberto da Microsoft](https://opensource.microsoft.com/codeofconduct/).  Para saber mais, confira as [Perguntas frequentes sobre o Código de Conduta](https://opensource.microsoft.com/codeofconduct/faq/) ou entre em contato pelo [opencode@microsoft.com](mailto:opencode@microsoft.com) se tiver outras dúvidas ou comentários.
