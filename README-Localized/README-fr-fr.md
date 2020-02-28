[![Badge de version npm](https://img.shields.io/npm/v/@microsoft/microsoft-graph-types.svg)](https://www.npmjs.com/package/@microsoft/microsoft-graph-types)

# Types TypeScript Microsoft Graph
Les définitions TypeScript Microsoft Graph permettent aux éditeurs de fournir des fonctionnalités IntelliSense sur les objets Microsoft Graph, notamment les utilisateurs, les messages et les groupes.

## Installation

Nous vous recommandons d’inclure le fichier .d.ts en téléchargeant ce package via [npm](https://www.npmjs.com/).

```bash

# Install types and save in package.json as a development dependency
npm install @microsoft/microsoft-graph-types --save-dev

```


![Image GIF montrant IntelliSense et la saisie semi-automatique des entités Microsoft Graph dans Visual Studio Code](https://github.com/microsoftgraph/msgraph-typescript-typings/raw/master/typings-demo.gif)
## Exemples
Les exemples suivants partent du principe que vous possédez un jeton d’accès valide. Nous avons utilisé [isomorphic-FETCH](https://www.npmjs.com/package/isomorphic-fetch) pour effectuer des requêtes, mais vous pouvez utiliser [notre bibliothèque cliente JavaScript](https://github.com/microsoftgraph/msgraph-sdk-javascript) ou d’autres bibliothèques également.
```typescript
import * as MicrosoftGraph from "@microsoft/microsoft-graph-types"

import * from 'isomorphic-fetch';
const accessToken:string = "";
```
### Répertorier mes messages récents
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
### Envoyer un e-mail en tant qu’utilisateur connecté
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
## Prise en charge de Microsoft Graph bêta
Si vous voulez tester les points de terminaison Microsoft Graph bêta, vous pouvez utiliser ces types simultanément avec les types v 1.0.

Mettez à jour votre fichier package.json avec ce qui suit :

```javascript
  "devDependencies": {
    // import published v1.0 types with a version from NPM
    "@microsoft/microsoft-graph-types": "^0.4.0",

    // import beta types from the beta branch on the GitHub repo
    "@microsoft/microsoft-graph-types-beta": "microsoftgraph/msgraph-typescript-typings#beta"
  }
}
```

Importez des types bêta de `@microsoft/microsoft-graph-types-beta`
```typescript
// import individual entities
import {User as BetaUser} from "@microsoft/microsoft-graph-types-beta"

// or import everything under MicrosoftGraphBeta
import * as MicrosoftGraphBeta from "@microsoft/microsoft-graph-types-beta"
```

## Éditeurs pris en charge
Tout projet TypeScript peut utiliser ces types avec au moins TypeScript 2.0. Nous avons testé l’inclusion des types en tant que dépendances dans les éditeurs suivants.
* Visual Studio Code
* WebStorm
* Atom avec le plug-in [atom-typescript](https://atom.io/packages/atom-typescript)

## Questions et commentaires

Nous serions ravis de connaître votre opinion sur le projet de définitions TypeScript. Vous pouvez nous faire part de vos questions et suggestions dans la rubrique [Problèmes](https://github.com/microsoftgraph/msgraph-typescript-typings/issues) de ce référentiel.


## Contribution
Reportez-vous aux [instructions sur la contribution](CONTRIBUTING.md).

## Ressources supplémentaires

* [Microsoft Graph](https://graph.microsoft.io)
* [Centre des développeurs Office](http://dev.office.com/)
* [Bibliothèque cliente JavaScript Microsoft Graph](https://github.com/microsoftgraph/msgraph-sdk-javascript)

## Génération de rapports de sécurité

Si vous rencontrez un problème de sécurité avec nos bibliothèques ou services, signalez-le à l’adresse [secure@microsoft.com](mailto:secure@microsoft.com) avec autant de détails que possible. Votre envoi vous donnera sans doute droit à une prime via le programme [Bounty de Microsoft](http://aka.ms/bugbounty). Merci de ne pas publier de problèmes de sécurité sur le site des problèmes GitHub ou sur un autre site public. Nous vous contacterons rapidement dès réception des informations. Nous vous encourageons à activer les notifications d’incidents de sécurité en vous rendant sur [cette page](https://technet.microsoft.com/en-us/security/dd252948) et en vous abonnant aux alertes d’avis de sécurité.

## Licence

Copyright (c) Microsoft Corporation. Tous droits réservés. Soumis à la licence MIT (la "Licence") ;

## Nous respectons le code de conduite Open Source de Microsoft.

Ce projet a adopté le [code de conduite Open Source de Microsoft](https://opensource.microsoft.com/codeofconduct/). Pour en savoir plus, reportez-vous à la [FAQ relative au code de conduite](https://opensource.microsoft.com/codeofconduct/faq/) ou contactez [opencode@microsoft.com](mailto:opencode@microsoft.com) pour toute question ou tout commentaire.
