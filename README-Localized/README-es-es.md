[![identificador de versión npm](https://img.shields.io/npm/v/@microsoft/microsoft-graph-types.svg)](https://www.npmjs.com/package/@microsoft/microsoft-graph-types)

# Tipos de TypeScript de Microsoft Graph
Las definiciones de TypeScript de Microsoft Graph permiten a los editores ofrecer IntelliSense en objetos de Microsoft Graph, como usuarios, mensajes y grupos.

## Instalación

Se recomienda incluir el archivo .d.ts al descargar este paquete a través de [npm](https://www.npmjs.com/).

```bash

# Install types and save in package.json as a development dependency
npm install @microsoft/microsoft-graph-types --save-dev

```


![GIF que muestra IntelliSense y finalización automática para entidades de Microsoft Graph en Visual Studio Code ](https://github.com/microsoftgraph/msgraph-typescript-typings/raw/master/typings-demo.gif)
## Ejemplos
En los ejemplos siguientes se presupone que el usuario tiene un token de acceso válido. Hemos usado [isomorphic-fetch](https://www.npmjs.com/package/isomorphic-fetch) para realizar solicitudes, pero también puede usar [nuestra biblioteca cliente de JavaScript](https://github.com/microsoftgraph/msgraph-sdk-javascript) u otras bibliotecas.
```typescript
import * as MicrosoftGraph from "@microsoft/microsoft-graph-types"

import * from 'isomorphic-fetch';
const accessToken:string = "";
```
### Mostrar mis mensajes recientes
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
### Enviar un correo electrónico como el usuario conectado
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
## Soporte de Microsoft Graph beta
Si desea probar los puntos de conexión de la versión beta de Microsoft Graph, puede usar esos tipos simultáneamente con los tipos v1.0.

Actualice el archivo package.json con lo siguiente:

```javascript
  "devDependencies": {
    // import published v1.0 types with a version from NPM
    "@microsoft/microsoft-graph-types": "^0.4.0",

    // import beta types from the beta branch on the GitHub repo
    "@microsoft/microsoft-graph-types-beta": "microsoftgraph/msgraph-typescript-typings#beta"
  }
}
```

Import the beta types from `@microsoft/microsoft-graph-types-beta`
```typescript
// import individual entities
import {User as BetaUser} from "@microsoft/microsoft-graph-types-beta"

// or import everything under MicrosoftGraphBeta
import * as MicrosoftGraphBeta from "@microsoft/microsoft-graph-types-beta"
```

## Editores admitidos
Cualquier proyecto TypeScript puede usar estos tipos al usar al menos TypeScript 2.0 Hemos probado a incluir los tipos como dependencia en los siguientes editores.
* Visual Studio Code
* WebStorm
* Atom with the [atom-typescript](https://atom.io/packages/atom-typescript) plugin

## Preguntas y comentarios

Nos encantaría recibir sus comentarios sobre el proyecto de definiciones de TypeScript. Puede enviarnos sus preguntas y sugerencias a través de la sección [Problemas](https://github.com/microsoftgraph/msgraph-typescript-typings/issues) de este repositorio.


## Colaboradores
Vea la [directrices de contribución](CONTRIBUTING.md).

## Recursos adicionales

* [Microsoft Graph](https://graph.microsoft.io)
* [Centro para desarrolladores de Office](http://dev.office.com/)
* [Biblioteca cliente de JavaScript de Microsoft Graph](https://github.com/microsoftgraph/msgraph-sdk-javascript)

## Informes de seguridad

Si encuentra un problema de seguridad con nuestras bibliotecas o servicios, informe a [secure@microsoft.com](mailto:secure@microsoft.com) con todos los detalles posibles. Es posible que el envío pueda optar a una recompensa a través del programa [Microsoft Bounty](http://aka.ms/bugbounty). No publique problemas de seguridad en problemas de GitHub ni ningún otro sitio público. Nos pondremos en contacto con usted rápidamente tras recibir la información. Le animamos a que obtenga notificaciones de los incidentes de seguridad que se produzcan; para ello, visite [esta página](https://technet.microsoft.com/en-us/security/dd252948) y suscríbase a las alertas de avisos de seguridad.

## Licencia

Copyright (c) Microsoft Corporation. Todos los derechos reservados. Publicado bajo la licencia MIT (la "Licencia").

## Valoramos y nos adherimos al Código de conducta de código abierto de Microsoft

Este proyecto ha adoptado el [Código de conducta de código abierto de Microsoft](https://opensource.microsoft.com/codeofconduct/). Para obtener más información, vea [Preguntas frecuentes sobre el código de conducta](https://opensource.microsoft.com/codeofconduct/faq/) o póngase en contacto con [opencode@microsoft.com](mailto:opencode@microsoft.com) si tiene otras preguntas o comentarios.
