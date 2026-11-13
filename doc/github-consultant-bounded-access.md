# Accès GitHub borné du Consultant — lot mécanisme (ACC-4308)

## Périmètre et absence d’application

Ce lot ne configure ni profil, ni policy, ni grant, ni connexion dans la société.
Les intentions `a737f60f-32f3-4ecd-b7e1-aba0e281fcb8` et
`af04848f-0ea7-414d-816b-66f41fde4839` doivent rester inchangées.
Les fixtures du banc ne s’écrivent que dans une base de test jetable.
Aucun OAuth, troisième intent, redémarrage ou déploiement n’est requis.

Source de cadrage : ACC-4298, document `decision`, révision
`1c504d7d` (13/11/2026) ; exécution Infra ultérieure : ACC-4217.

## Identité : refus explicite plutôt qu’identité inférée

Un `connection_grants.kind = organization` représente une autorisation partagée,
pas une identité d’agent. La contrainte SQL impose que ses deux sujets
`subjectUserId` et `subjectAgentId` soient nuls. Le sélecteur managed reste donc
inchangé : agent dédié, utilisateur responsable, délégation admissible.
Aucun fallback organisationnel n’est ajouté.

Dans le relevé du 13/11, le grant organisationnel visible de `181a5395-…`
a `providerTenant = null` et une référence `credentials.authorization`.
Le resolver managed exige au contraire `providerTenant.github` et
`oauth.access_token`. Ajouter `organization` au filtre SQL ne résoudrait donc
pas l’identité. Cela exigerait en outre une règle d’audience, une attribution
explicite et une politique de non-export ; le bearer seul ne prouve rien.

**Limite de l’inventaire antérieur :** GET grants filtre les grants personnels
et agents pour un appelant non-manager. Une liste contenant uniquement le grant
organisationnel ne prouve pas son unicité. Le broker a effectivement résolu un
grant `dedicated` pour Dev Plateforme pendant le diagnostic, sans afficher le
jeton. Ce contrôle n’est pas une preuve d’identité pour le Consultant.
Les sept consommateurs existants ne sont ni migrés ni reconfigurés.
Le parcours OAuth par-agent abandonné n’est pas réintroduit.

L’option « refus documenté » du livrable 1 est retenue. Le lot ne prétend pas que
le Consultant peut déjà utiliser la connexion ; Infra doit conserver ce refus
et ne pas compléter les intents sur la seule foi du transport sain.

## Installation : transport sans héritage du profil complet

Pour une nouvelle installation MCP à la demande, la liaison automatique au
profil `app:{connectionId}` n’est pas créée. Le profil minimal doit être préparé
séparément ; installer le transport ne lui ajoute pas les 50 entrées de l’app.

Une cible peut aussi demander `bindAppProfile: false` dans son objet `installs`
(la valeur `true` n’est pas une nouvelle capacité publique). L’autorisation de
modifier cette cible s’applique même si sa ligne d’installation existe déjà.
Dans la transaction verrouillée, la liaison app de cette cible est retirée avant
la création de l’installation. Aucune entrée du catalogue, aucun autre profil,
aucune liaison d’un autre agent ne sont supprimés.

Exemple de payload, à préparer par Infra mais **ne pas appliquer dans ce lot** :

```json
{
  "installs": [
    {"targetType":"agent","targetId":"<agent existant conservé>"},
    {"targetType":"agent","targetId":"<Consultant>","bindAppProfile":false}
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
schéma ; elle ne remplace pas le profil minimal. Les entrées actives déjà
revues ne sont pas révoquées globalement, afin de préserver les consommateurs.

## Broker : frontière réelle de dispatch

Les mutations GitHub bornées sont revérifiées dans `executeRemoteHttpTool`,
après résolution du grant, avant client fournisseur et acquisition des headers.
Les vrais arguments du dispatch (y compris ceux d’une requête approuvée) passent
à l’évaluateur commun. Aucun résultat de préflight fourni par l’appelant ne fait
foi.

Une policy d’arguments explicitement liée à l’agent **et** à la connexion active
le contrôle borné. Il faut un grant managed actif avec identité GitHub résolue,
un couple exact `(owner, repo)`, et un verdict `allow_policy` dont la policy
correspondante contient **les deux** valeurs dans le même `fieldEquals`.
Un `allow_profile`, un grant large ou un `require_approval` ne suffisent pas.
Les policies `block` correspondantes priment sur un `allow`, même si leur
priorité numérique vient après.

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
pnpm exec vitest run server/src/__tests__/github-consultant-reference.test.ts server/src/__tests__/github-transport-only-installs.test.ts server/src/__tests__/github-catalog-quarantine.test.ts server/src/__tests__/github-managed-organization-identity.test.ts server/src/__tests__/github-broker-boundary.test.ts server/src/__tests__/github-broker-integration.test.ts
```

Sur la flotte, utiliser `build-mcp.build_step` sur le SHA exact avec `test-path`
pour chaque fichier, puis `build_status`. Le service ne reçoit aucune clé ni
aucun payload de configuration de la connexion réelle.
Le JSON de cas est `server/src/__tests__/fixtures/github-consultant-policy-cases.json`.
Le banc HTTP appelle réellement `/tools/policy/test` avec
`consumeRateLimit:false` et `writeAuditEvent:false`, sans appel fournisseur.
Un fichier skipped n’est pas un banc passé ; relever le nombre exécuté.

Le banc inclut une édition scalaire `create_or_update_file` limitée aux quatre
chemins exacts, avec `owner`, `repo` et branche dans le même `fieldEquals` et
`path` dans `fieldIn`. Les variantes mauvais owner/repo, chemin absent, autre
fichier et traversée de chemin sont refusées. Les modifications de contenu
elles-mêmes restent à valider dans ACC-4108 : une borne de chemin ne vérifie pas
que seul `structured_output` change.
`push_files` reste exclu : le AND sur un chemin scalaire ne prouve pas que chaque
élément de `files[]` respecte ces quatre fichiers. Aucun répertoire n’est ouvert.
Infra doit fournir une preuve distincte avant d’activer l’écriture par lot.

## Premières preuves exécutées (pas un verdict final)

Moteur `build-mcp` : `0d84b7cf2800931caa222f071d4d79f8488208fed5b619db0587b5c4d904720d`.
Les deux jobs ci-dessous ont tourné sous UID/GID 1000, réseau coupé pour le test,
caches node_modules / cargo / pnpm warm ; aucun OOM.

| SHA | Job / étape | Résultat | Durée étape / pic |
|---|---|---|---|
| `df9006671bb3636f9c510778ef58ff7fe4e69e7f` | `e1603f4d-19b8-4625-a4ed-b2c295eee597`, github-operation-credentials | rc 0 ; 26 passés, 0 skipped | 44 s / 1666 Mo |
| `fc0cf2fab40cda2f2b1d4c7de83105befb85fc5c` | `fa04c202-9919-4c53-878d-ab2823aedd0b`, tests nouveaux avant correctif | rc 1 ; 18 échecs, 1 passé, 0 skipped | 40 s / 2175 Mo |
| `2c716e7014219fac9aec9eac760811648ecd3f66` | `8eac4736-f776-45ad-a557-f2e8ffa50435`, installation corrigée | rc 0 ; 19 passés, 0 skipped | 38 s / 1870 Mo |

Le RED établit notamment `app binding still present before reach insert`,
la recréation d’un profil complet pour le nouvel agent et l’absence d’autorisation
sur unbind d’une cible inchangée. Ce SHA test-first n’est pas une version livrable.
Le résultat GREEN doit être relevé sur le SHA qui porte le correctif ; ces résultats
antérieurs ne le remplacent pas.

## Impact, retour arrière et preuve attendue

Pas de migration de données, dépendance cloud ou secret ajouté.
Le changement de priorité des blocks peut refuser un allow historiquement plus
prioritaire : c’est le comportement de sécurité annoncé, à vérifier en QA.
Le retour arrière est le revert de la PR, pas une restauration de credentials.
Aucun retour arrière runtime n’est effectué par ce lot.

Livraison complète uniquement après contrôles exécutés au SHA de la PR : banc,
régression des consommateurs, interruption et résultats CI réels. Ce document
ne constitue pas une attestation de réussite des tests.
