# Recettes Ansible pour Article714

**AVERTISSEMENT: cet outillage n'est plus compatible avec python2**

Ce dépôt contient l'ensemble de l'outillage d'administration Article714,
sur base [Ansible](http//ansible.com)

Cet outillage ne peut pas être utilisé en tant que tel mais doit être complété de
fichiers de configuration permettant de décrire l'infastructure sur la quelle les
'recettes' s'appliquent.

Certains des rôles utilisés ici sont largement inspirés, voire contiennent du code issus d'autres rôles Ansible, notamment:

- le role _odoo-node_ ré-utilise les templates et leur paramétrage venant de https://github.com/OCA/ansible-odoo (GPL-V3 license)

Un complément de documentation se trouve dans le répertoire [documentation](documentation/index.md).

## Mise en oeuvre d'Ansible sur une machine d'admin

En suivant les étapes ci-desssous, on obtient un répertoire contenant les éléments nécessaires à l'exécution des playbooks du projet Ansible714.

Il faut ensuite personnalisé le contenu de l'inventaire Ansible pour le faire coïncider avec l'environnement cible à piloter.

### Création du virtualenv _(facultatif)_

1. Installation de `virtualenv`, `virtualenvwrapper`, `python3` sur la machine cliente

   /ex. sur Debian ou Ubuntu:
   `apt-get install virtualenv virtualenvwrapper python3`

2. Création de l'environnement virtuel (_virtualenv_) 'ansible'

   `mkvirtualenv -p /usr/bin/python3 ansible`

3. Installation dans le virtualenv ansible des dépendances:

   ```shell
   workon ansible
   # dépendances d'exécution
   pip install --upgrade -r requirements.txt
   # dépendances pour le développement
   pip install --upgrade -r requirements_dev.txt
   ```

   Les fichiers _requirementss.txt_ se trouve à la racine du dépôt

### Création d'un inventaire

Dans cette étape, on initialise l'aborescence qui contiendra l'outillage Ansible714 et les fichiers d'inventaire.

_C'est à partir de ce répertoire que pourront être exécutés les playbooks Ansible_

1. Création du répertoire cible
2. intialisation de l'arborescence via le script `./scripts/build_inventory_dir.sh <inventory directory full path>`
3. Mise à jour des recettes, dans le répertoire de l'inventaire:
   `./init_all_roles.sh`
4. On teste si le tout fonctionne

   ```shell
   workon ansible
   ansible all -m ping
   ```

Les fichiers par défaut posés dans le répertoire `inventory` peuvent ensuite être modifiés pour s'adapter à l'environnement cible.

## Exécution des playbooks

1. S'assurer que la configuration des machines est correcte dans l'inventaire:

   - dans le fichier **./inventory/hosts**, qui fait l'inventaire des machines et de leurs groupes
   - dans les fichiers **./inventory/host_vars/\***, où se trouve les variables de configuration spécifiques à chaque machine

2. Exécuter le playbook souhaité:

   par exemple:

   ```shell
   ansible-playbook [--ask-vault-pass] playbooks/update-debian-software.yml
   ```

   l'option _--ask-vault-pass_ est à spécifier si il est nécessaire de fournir un mot de passe pour déchiffrer certaines valeurs (voir section suivante)

## Gestion des mots de passe et données secrètes

Ansible permet de [chiffrer les données sensibles](https://docs.ansible.com/ansible/latest/user_guide/vault.html)

Certains mots de passe sont ainsi chiffrés dans les fichiers de configuration ou les variables. Cela peut être fait
en utilisant des commandes du type:
`echo -n 'Bonjour' | ansible-vault --ask-vault-pass encrypt_string --stdin-name 'api_password'`

Les mots de passe ainsi chiffrés ont été stockés dans le fichier \*./inventory/vars/\_secrets.yml

## Exemple, une fois tout mis bout à bout

/ex. lancement de la mise à jour/installation des serveurs web

```shell
ansible-playbook  --ask-vault-pass playbooks/webservers.yml
```
