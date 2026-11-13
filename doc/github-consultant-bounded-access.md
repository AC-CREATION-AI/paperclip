# Accès GitHub borné d’un agent consultant — lot mécanisme

## Périmètre et absence d’application

Ce lot ne configure ni profil, ni policy, ni grant, ni connexion dans la société.
Les intentions de connexion en attente doivent rester inchangées.
Les fixtures du banc ne s’écrivent que dans une base de test jetable ; owners,
dépôts, branches et chemins y sont synthétiques.
Aucun OAuth, nouvel intent, redémarrage ou déploiement n’est requis.
Les références de suivi internes (tickets, identifiants d’instance) restent hors
du dépôt.

## Identité : refus explicite plutôt qu’identité inférée

Un `connection_grants.kind = organization` représente une autorisation partagée,
pas une identité d’agent. La contrainte SQL impose que ses deux sujets
`subjectUserId` et `subjectAgentId` soient nuls. Le sélecteur managed reste donc
inchangé : agent dédié, utilisateur responsable, délégation admissible.
Aucun fallback organisationnel n’est ajouté.

Sur une connexion partagée observée, le grant organisationnel visible
a `providerTenant = null` et une référence `credentials.authorization`.
Le resolver managed exige au contraire `providerTenant.github` et
`oauth.access_token`. Ajouter `organization` au filtre SQL ne résoudrait donc
pas l’identité. Cela exigerait en outre une règle d’audience, une attribution
explicite et une politique de non-export ; le bearer seul ne prouve rien.

**Limite de l’inventaire antérieur :** GET grants filtre les grants personnels
et agents pour un appelant non-manager. Une liste contenant uniquement le grant
organisationnel ne prouve pas son unicité. La résolution d’un grant `dedicated`
pour un autre agent pendant le diagnostic n’est pas une preuve d’identité pour
le consultant. Les consommateurs existants ne sont ni migrés ni reconfigurés.
Le parcours OAuth par-agent abandonné n’est pas réintroduit.

L’option « refus documenté » du livrable 1 est retenue. Le lot ne prétend pas que
le consultant peut déjà utiliser la connexion ; l’exploitation doit conserver ce refus
et ne pas compléter les intents sur la seule foi du transport sain.

## Installation : transport sans héritage du profil complet

Le chemin outillé est `bindAppProfile:false` dans la liste `installs`. Le drapeau
`config.onDemandTools` est seulement lu : aucun code applicatif ni UI du dépôt
ne l’écrit. Son éventuelle présence dans une configuration existante ne constitue
pas un parcours de configuration disponible aux agents.

Pour une nouvelle installation MCP portant déjà ce drapeau, la liaison automatique
au profil `app:{connectionId}` n’est pas créée. Le profil minimal doit être préparé
séparément ; installer le transport ne lui ajoute pas les 50 entrées de l’app.

Une cible peut aussi demander `bindAppProfile: false` dans son objet `installs`
(la valeur `true` n’est pas une nouvelle capacité publique). L’autorisation de
modifier cette cible s’applique même si sa ligne d’installation existe déjà.
Dans la transaction verrouillée, la liaison app de cette cible est retirée avant
la création de l’installation. Aucune entrée du catalogue, aucun autre profil,
aucune liaison d’un autre agent ne sont supprimés.

Exemple de payload, à préparer par l’exploitation mais **ne pas appliquer dans ce lot** :

```json
{
  "installs": [
    {"targetType":"agent","targetId":"<agent existant conservé>"},
    {"targetType":"agent","targetId":"<consultant>","bindAppProfile":false}
  ]
}
```

Conserver toutes les autres cibles lors d’un PUT remplaçant la liste.
Les installations existantes omises seraient désinstallées : ce n’est pas un
PATCH additif.

### Interruption et réconciliation

Avant commit, l’échec annule le retrait de liaison et l’insertion de la portée
transport ensemble. Après commit, l’absence de liaison app est durable. Un
rejeu de la même demande ne recrée pas la liaison : seuls les ajouts admissibles
peuvent la créer, et `bindAppProfile:false` impose à nouveau son retrait.
Il n’existe donc plus de seconde étape `unbind` à terminer après installation
pour ce parcours. Si une liaison app au niveau société survit et accorderait les
outils au même agent, la transition transport-only est refusée : retirer cette
liaison plus large doit faire l’objet d’une décision distincte, jamais d’une
suppression implicite affectant les autres consommateurs.
Ne pas appeler ensuite `/finish` en activant le profil complet :
ce serait une nouvelle décision d’accès, pas une réconciliation.

La quarantaine GitHub protège les nouvelles définitions et changements de
schéma ; elle ne remplace pas le profil minimal. `quarantineNewEntries:true`
est volontairement le défaut de toute nouvelle connexion GitHub (managed ou
PAT `mcp-key`) et reste vrai après reconnexion. C’est un changement de contrat
par rapport à la base : création et rotation de credential ne valent plus
approbation implicite des outils. Un `/finish` explicite peut approuver les
entrées sélectionnées ; une reconnexion seule laisse les entrées déjà en attente
et les nouvelles entrées en quarantaine, sans les inclure dans le profil.
Les entrées actives déjà revues et inchangées ne sont pas révoquées globalement,
afin de préserver les consommateurs. Aucun changement runtime n’est appliqué
par ce lot. Les deux tests de galerie couvrent cette évolution, la rotation en
place du secret et la conservation des choix Ask-first.

## Broker : frontière réelle de dispatch

Les mutations GitHub bornées sont revérifiées dans `executeRemoteHttpTool` et
`executeLocalStdioTool`, après résolution du grant, avant client fournisseur et
acquisition des headers.

La frontière ne se fie pas au `riskLevel` du catalogue ni aux annotations du
fournisseur : GitHub n’a pas de classifieur revu, et le classifieur générique
range par exemple `merge_pull_request`, `fork_repository`, `push_files` et
`add_issue_comment` en `read`. Seuls les outils de lecture revus listés dans
`github-policy-scope.ts` sont exemptés, et uniquement s’ils sont stockés en
`read`. Tout autre outil, y compris inconnu ou renommé, passe par le broker
(défaut fermé). Une entrée déjà active en `read` est donc couverte sans
republication du catalogue. Les consommateurs sans policy bornée conservent
leur contrat : le broker revient immédiatement.
Les vrais arguments du dispatch (y compris ceux d’une requête approuvée) passent
à l’évaluateur commun. Aucun résultat de préflight fourni par l’appelant ne fait
foi.

Une policy d’arguments explicitement liée à l’agent **et** à la connexion active
le contrôle borné. Il faut un grant managed actif avec identité GitHub résolue,
un couple exact `(owner, repo)`, et un verdict `allow_policy` dont la policy
correspondante contient **les deux** valeurs dans le même `fieldEquals`.
Un `allow_profile`, un grant large ou un `require_approval` ne suffisent pas.
Uniquement pour une connexion GitHub persistée et un agent soumis à une policy
d’arguments explicitement agent+connexion, les policies `block` correspondantes
priment sur un `allow`, même si leur priorité numérique vient après. La présence
de bornes est déterminée avant filtrage des arguments : un appel hors borne ne
peut pas désactiver ce contrôle. Les connexions non-GitHub et les consommateurs
GitHub non bornés conservent l’ordre numérique historique (première règle
correspondante). Une `applicationKey` fournie par l’appelant ne change pas ce
périmètre.

L’évaluateur combine bien `fieldEquals:{owner,repo}` avec d’autres prédicats
(`fieldIn.path`, `fieldEquals.base_ref`, etc.) dans une même condition : AND
entre champs et groupes. Des listes indépendantes owner/repo créeraient un
produit cartésien et ne sont pas utilisées par le banc.

### Pas d’export de jeton pour un accès borné

Une fois un PAT brut remis à `git` ou `gh`, aucun contrôle d’arguments Paperclip
ne peut empêcher ses autres usages. Le resolver refuse donc l’export brut dès
qu’une policy d’arguments agent+connexion indique un accès borné. Il refuse
également si la lecture de ces contrôles échoue. Les consommateurs sans accès
borné conservent leur contrat historique ; aucun nouveau droit n’est appliqué.

Ce lot ne livre pas un service exécutant arbitrairement `git push` côté serveur.
Les mutations bornées utilisent uniquement le dispatch d’outils gouvernés.
Le shell ne peut pas transformer un préflight positif en jeton général.

## Banc de référence

Commande unique dans un environnement de test isolé muni des dépendances et
d’embedded PostgreSQL (pas dans le conteneur Paperclip partagé) :

```sh
pnpm exec vitest run server/src/__tests__/github-consultant-reference.test.ts server/src/__tests__/github-transport-only-installs.test.ts server/src/__tests__/github-catalog-quarantine.test.ts server/src/__tests__/github-managed-organization-identity.test.ts server/src/__tests__/github-broker-boundary.test.ts server/src/__tests__/github-broker-integration.test.ts server/src/__tests__/tool-access-service.test.ts
```

Dans un service de build isolé, lancer chaque fichier au SHA exact. Ce service
ne reçoit aucune clé ni aucun payload de configuration de la connexion réelle.
Le JSON de cas est `server/src/__tests__/fixtures/github-consultant-policy-cases.json`.
Le banc HTTP appelle réellement `/tools/policy/test` avec
`consumeRateLimit:false` et `writeAuditEvent:false`, sans appel fournisseur.
Un fichier skipped n’est pas un banc passé ; relever le nombre exécuté.

Le banc inclut une édition scalaire `create_or_update_file` limitée aux quatre
chemins exacts, avec `owner`, `repo` et branche dans le même `fieldEquals` et
`path` dans `fieldIn`. Les variantes mauvais owner/repo, chemin absent, autre
fichier et traversée de chemin sont refusées. Les modifications de contenu
elles-mêmes restent à valider séparément : une borne de chemin ne vérifie pas
que seul `structured_output` change.
`push_files` reste exclu : le AND sur un chemin scalaire ne prouve pas que chaque
élément de `files[]` respecte ces quatre fichiers. Aucun répertoire n’est ouvert.
L’exploitation doit fournir une preuve distincte avant d’activer l’écriture par lot.

## Preuves d’exécution

Les identifiants de jobs, durées et SHA des exécutions sont conservés dans le
suivi interne, pas dans ce document. Un SHA test-first n’est pas une version
livrable ; le résultat GREEN doit être relevé sur le SHA qui porte le correctif.

## Impact, retour arrière et preuve attendue

Pas de migration de données, dépendance cloud ou secret ajouté.
Le tri block-first global de la première version a été rejeté en revue : des
rôles existants possèdent, sur une connexion non-GitHub, un allow de découverte
sans arguments (priorité 0) qui recouvre un block de commande absente
(priorité 1). Le tri global supprimerait cette découverte.
Le correctif borne le tri aux seuls accès GitHub bornés et conserve le verdict
allow historique de ces connexions non-GitHub. Le banc rejoue cette paire de
conditions chevauchantes, y compris avec une fausse `applicationKey:"github"`.
Aucune policy existante n’est réécrite ni aucune permission ajoutée.

La qualification globale reste ouverte : les workflows du fork délèguent aux
runners amont et aucun run de PR n’a été observé lors de la revue. Le build global
(`COPILOT_INSTALLATION_INVALID`) et la suite globale (collecte plugin-sdk) échouent
également sur la base inchangée. Les tests ciblés ne remplacent ni une CI verte
ni la décision de qualification correspondante ; aucune fusion n’est demandée.
Le retour arrière est le revert de la PR, pas une restauration de credentials.
Aucun retour arrière runtime n’est effectué par ce lot.

Livraison complète uniquement après contrôles exécutés au SHA de la PR : banc,
régression des consommateurs, interruption et résultats CI réels. Ce document
ne constitue pas une attestation de réussite des tests.
