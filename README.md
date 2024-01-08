# SecTrans

Projet réalisé par Arnaud Avocat Gros, Samuel Bois, Julian Dezarnaud et Alexis Malosse

## Pré-requis

Modifier le LD_LIBRARY_PATH pour que le compilateur puisse trouver les librairies:
```
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./lib
```

Installer openssl
```
  sudo apt-get install libssl-dev
```

## Utilisation

Pour lancer le serveur:
```
  make run_server
```
Ou encore (si déjà compilé)
```
  ./server
```

Pour compiler le client:
```
  make client
```
Pour utiliser le client:
```
  ./sectrans <parameter>
```
Exemple :
```
  ./sectrans -up <file>
```
```
  ./sectrans -list
```
```
  ./sectrans -down <file>
```
## Comptes utilisateurs
Login: samuel | Mot de passe: pwd1

Login: arnaud | Mot de passe: pwd2

Login: alexis | Mot de passe: pwd3

Login: julian | Mot de passe: pwd4
  
