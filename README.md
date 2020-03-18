# Recettes Ansible pour Article714

Ce dépôt contient l'ensemble de l'outillage d'administration Article714,
sur base [Ansible](http//ansible.com)

Cet outillage ne peut pas être utilisé en tant que tel mais doit être complété de
fichiers de configuration permettant de décrire l'infastructure sur la quelle les
'recettes' s'appliquent.

Certains des rôles utilisés ici sont largement inspirés, voire contiennent du code issus d'autres rôles Ansible, notamment:
* le role *odoo-node* ré-utilise les templates et leur paramétrage venant de https://github.com/OCA/ansible-odoo (GPL-V3 license)


## Répertoire (dépôt) d'inventaire utilisant les recettes Ansible714

### Création d'un inventaire

**initialisation de l'aborescence:**

1. Création du répertoire cible
2. intialisation de l'arborescence via le script `./scripts/build_inventory_dir.sh <inventory directory full path`

### Mise à jour des recettes

Dans le répertoire de l'inventaire:
`./init_all_roles.sh`

## Mise en oeuvre d'Ansible sur une machine d'admin

### Création du virtualenv (python)

1. Installation de `virtualenv`, `virtualenvwrapper`, `python3` sur la machine cliente

   /ex. sur Debian ou Ubuntu:
   `apt-get install virtualenv virtualenvwrapper python3`

2. Création de l'environnement virtuel (_virtualenv_) 'ansible'

   `mkvirtualenv -p /usr/bin/python3 ansible`

3. Installation dans le virtualenv ansible des dépendances:

   ```shell
   workon ansible
   pip install --upgrade -r requirements.txt
   ```

   Le fichier _requirements.txt_ se trouve à la racine du dépôt

4. Initialisation des modules _foreign_ et des modules _galaxy_ qu'on utilise dans les scripts

   ```shell
   ./init_all_roles.sh
   ```

5. On teste si le tout fonctionne

   ```shell
   workon ansible
   ansible all -m ping
   ```

   This command will try to connect to each host in the **./hosts** inventory files

### Exécution des playbooks

1. S'assurer que la configuration des machines est correcte dans l'inventaire:

   - dans le fichier **./inventory/hosts**, qui fait l'inventaire des machines et de leurs groupes
   - dans les fichiers **./inventory/host_vars/\***, où se trouve les variables de configuration spécifiques à chaque machine

2. Exécuter le playbook souhaité:

   par exemple:

   ```shell
   ansible-playbook [--ask-vault-pass] playbooks/update-debian-software.yml
   ```

   l'option _--ask-vault-pass_ est à spécifier si il est nécessaire de fournir un mot de passe pour déchiffrer certaines valeurs (voir section suivante)

### Gestion des mots de passe et données secrètes

Ansible permet de [chiffrer les données sensibles](https://docs.ansible.com/ansible/latest/user_guide/vault.html)

Certains mots de passe sont ainsi chiffrés dans les fichiers de configuration ou les variables. Cela peut être fait
en utilisant des commandes du type:
`echo -n 'Bonjour' | ansible-vault --ask-vault-pass encrypt_string --stdin-name 'api_password'`

Les mots de passe ainsi chiffrés ont été stockés dans le fichier \*./inventory/vars/\_secrets.yml

### Tout mis bout à bout

/ex. lancement de la mise à jour/installation des serveurs web

```shell
ansible-playbook  --ask-vault-pass playbooks/webservers.yml
```
