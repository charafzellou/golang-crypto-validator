# Défi de cryptographie : Protocole de communication sécurisée

## Aperçu
Dans cet exercice, vous allez implémenter une application client qui interagit avec un serveur sécurisé pour réaliser une série de défis cryptographiques. L'objectif est de renforcer votre compréhension des concepts cryptographiques fondamentaux tout en simulant des protocoles de communication sécurisés du monde réel.

## Objectifs
À la fin de ce défi, vous devriez être capable de :
1. Implémenter des opérations cryptographiques de base (hachage et chiffrement)
2. Interagir avec une API RESTful en utilisant des protocoles sécurisés
3. Gérer et répondre à des défis cryptographiques sensibles au temps
4. Gérer un système simple basé sur des scores dans un environnement compétitif

## Le défi
Votre tâche consiste à créer une application client qui communique avec un serveur fourni. Le serveur émettra deux types de défis cryptographiques : des défis de hachage et des défis de chiffrement. Votre client doit résoudre ces défis correctement pour gagner des points. Le premier étudiant à atteindre 30 points remporte le défi.

### Points d'accès du serveur
Le serveur fournit les points d'accès suivants :

1. `/subscribe` (POST) : Enregistrez votre client auprès du serveur
2. `/info/{address}` (GET) : Récupérez votre score actuel et vos informations
3. `/challenge/hash/{address}` (GET) : Demandez un défi de hachage
4. `/challenge/hash/{address}/{challengeID}` (POST) : Soumettez une solution au défi de hachage
5. `/challenge/encrypt/{address}` (GET) : Demandez un défi de chiffrement
6. `/challenge/encrypt/{address}/{challengeID}` (POST) : Soumettez une solution au défi de chiffrement

### Types de défis

1. **Défi de hachage** : 
   - Le serveur fournit une phrase aléatoire.
   - Votre tâche consiste à calculer le hachage SHA256 de la phrase et à le renvoyer au serveur.

2. **Défi de chiffrement** :
   - Le serveur fournit une phrase aléatoire et une clé publique.
   - Votre tâche consiste à chiffrer la phrase en utilisant la clé publique fournie et à renvoyer le texte chiffré au serveur.

### Système de points
- Chaque défi réussi vous rapporte 1 point.
- Chaque tentative échouée entraîne une déduction de 3 points.
- Le premier étudiant à atteindre un score de 30 remporte le défi.

## Exigences
1. Implémentez une application client dans un langage de programmation de votre choix.
2. Votre client doit être capable de :
   - S'abonner au serveur avec une adresse Ethereum valide et un nom
   - Récupérer les informations sur le score actuel
   - Demander et résoudre les défis de hachage et de chiffrement
   - Gérer les erreurs avec élégance et continuer à fonctionner
3. Implémentez une gestion appropriée des erreurs et une journalisation dans votre application client.
4. Assurez-vous que votre client peut gérer des défis simultanés et maintenir un état cohérent.

## Défis bonus
Pour des points supplémentaires, envisagez d'implémenter les fonctionnalités suivantes :
1. Une interface utilisateur pour afficher le score actuel et l'état des défis
2. La réessai automatique des défis échoués avec un backoff exponentiel
3. L'implémentation d'algorithmes cryptographiques supplémentaires au-delà de ceux requis

## Soumission
Soumettez le code de votre application client accompagné d'un bref rapport décrivant :
1. Votre approche d'implémentation
2. Les défis auxquels vous avez été confronté et comment vous les avez surmontés
3. Les améliorations ou optimisations potentielles que vous apporteriez avec plus de temps

Bonne chance, et que le meilleur cryptographe gagne !