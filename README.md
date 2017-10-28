# SteganoPngLsb

Permet de cacher un message crypté dans une image de type PNG en utilisant la méthode LSB.

Le message est d'abord crypté en utilisant RSA-CBC-256 puis caché dans les bits de poids faible de l'image PNG.

## Capacité de stockage

La capacité de stockage de l'image utilisée dépand de son format. Généralement 3 couleurs sont utilisées plus l'alpha. Ce qui nous fait 4bits par pixel.

## Fonctionnement

1. L'utilisateur entre le message à crypter
2. L'utilisateur entre le chemin de l'image dans laquelle il veut garder le message crypté
3. Le programme vérifie qu'il y aura assez de place pour stocker le message
4. Si l'espace de stockage de l'image est suffisant, l'utilisateur rentre une passphrase. Sinon il est renvoyé à l'étape 2.

## Bibliothèques utilisées

- openSSL
- libpng
