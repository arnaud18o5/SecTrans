# SecTrans

Modifier le LD_LIBRARY_PATH pour que le compilateur puisse trouver les librairies:
```
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./lib
```

Installer openssl
```
  sudo apt-get install libssl-dev
```

Pour lancer le serveur:
```
  make run_server
```

Pour utiliser le client:
```
  make client
```

```
  ./client <parameter>
```

  
