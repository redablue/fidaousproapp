# Installation Fidaous Pro - Procédure en Une Commande

## Prérequis Système

### Serveur Requis
Un serveur Debian 12 (Bookworm) fraîchement installé avec un accès root complet. Le serveur doit disposer d'au minimum 8 GB de RAM, 4 cœurs processeur et 500 GB d'espace disque SSD. Une connexion Internet stable avec une adresse IP fixe est également nécessaire pour l'installation des dépendances et la configuration des certificats SSL.

### Configuration DNS
Avant de procéder à l'installation, configurez les enregistrements DNS suivants chez votre fournisseur de domaine. L'enregistrement A principal doit pointer votre domaine (exemple: fidaouspro.com) vers l'adresse IP publique de votre serveur. Un enregistrement CNAME pour le sous-domaine Nextcloud (cloud.fidaouspro.com) doit également être configuré pour pointer vers le domaine principal.

## Installation Automatique

### Commande d'Installation Unique

L'installation complète de Fidaous Pro s'effectue avec une seule commande qui télécharge et exécute le script d'installation automatique. Cette commande doit être exécutée en tant que root sur votre serveur Debian 12.

```bash
curl -sSL https://install.fidaouspro.com/install.sh | bash
```

Alternativement, si vous préférez examiner le script avant son exécution, vous pouvez le télécharger puis l'exécuter manuellement :

```bash
wget https://install.fidaouspro.com/install.sh
chmod +x install.sh
./install.sh
```

### Installation avec Configuration Personnalisée

Pour une installation avec des paramètres prédéfinis, vous pouvez spécifier les variables d'environnement avant l'exécution du script :

```bash
DOMAIN_NAME="votre-domaine.com" \
NEXTCLOUD_DOMAIN="cloud.votre-domaine.com" \
EMAIL_ADMIN="admin@votre-domaine.com" \
curl -sSL https://install.fidaouspro.com/install.sh | bash
```

## Processus d'Installation

### Phase de Configuration Interactive
Si les variables d'environnement ne sont pas prédéfinies, le script d'installation vous demandera de saisir interactivement les informations suivantes. Vous devrez fournir votre nom de domaine principal, le sous-domaine souhaité pour Nextcloud, et une adresse email valide pour l'enregistrement des certificats SSL.

### Progression Automatique
Le script d'installation procède ensuite automatiquement à travers toutes les étapes de configuration. Il met à jour le système Debian, installe et configure Apache, MySQL et PHP avec les paramètres optimisés pour Fidaous Pro. L'installation de Nextcloud s'effectue avec une configuration automatique des bases de données et des permissions appropriées.

La configuration des certificats SSL s'effectue automatiquement via Let's Encrypt, garantissant une connexion sécurisée dès la mise en service. Le script configure également les tâches automatiques, les sauvegardes quotidiennes et les mesures de sécurité système incluant le pare-feu et la protection contre les intrusions.

## Finalisation Post-Installation

### Accès à l'Application
Une fois l'installation terminée, l'application Fidaous Pro devient immédiatement accessible via votre nom de domaine configuré avec HTTPS. L'interface Nextcloud est également disponible sur le sous-domaine configuré. Le script génère automatiquement un rapport d'installation détaillé contenant toutes les informations de connexion et les mots de passe générés.

### Configuration Initiale Obligatoire
La première connexion à Fidaous Pro doit s'effectuer avec les identifiants administrateur par défaut fournis dans le rapport d'installation. Il est impératif de modifier immédiatement le mot de passe administrateur par défaut pour des raisons de sécurité. La configuration des informations du cabinet, la création des comptes utilisateurs et la personnalisation des paramètres fiscaux constituent les étapes suivantes essentielles.

### Vérification du Fonctionnement
Le script d'installation inclut des tests automatiques vérifiant le bon fonctionnement de tous les composants. Ces tests valident la connectivité des services Apache et MySQL, l'accessibilité de Nextcloud et l'activation des mesures de sécurité. En cas de problème détecté, les logs détaillés permettent d'identifier rapidement la cause et d'apporter les corrections nécessaires.

## Support et Dépannage

### Logs et Monitoring
L'installation génère des logs détaillés enregistrés dans /var/log/fidaous-install.log permettant de tracer chaque étape du processus d'installation. Ces logs constituent la première ressource de diagnostic en cas de problème. Le rapport d'installation final contient également les commandes utiles pour la surveillance continue du système.

### Procédures de Récupération
En cas d'échec de l'installation, le script peut être relancé après correction des problèmes identifiés. Les sauvegardes automatiques programmées permettent une récupération rapide en cas de problème ultérieur. La documentation fournie inclut les procédures de maintenance préventive et de résolution des incidents les plus courants.

Cette approche d'installation en une commande simplifie considérablement le déploiement de Fidaous Pro tout en garantissant une configuration professionnelle et sécurisée adaptée aux exigences des cabinets comptables.