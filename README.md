# URLCode admin

An optional administration extension backed by URLCode auth's service API. It supplies permission-gated pages for accounts, roles, sessions, audit records, registration approvals, administrative cases and explicit support impersonation. It does not replace URLCode's private runtime management endpoints or edit project YAML.

This is an actively reviewed Node/SQLite implementation. The full dashboard/detail/reporting workflows in the design proposal are not all complete. Local tests are not independent security review, real-provider deployment evidence or an accessibility certification. See [SECURITY.md](SECURITY.md).

## Build from reviewed local repositories

These packages are private and unpublished. The core runtime must include the reviewed generic extension contract from [core PR #59](https://github.com/jimhoyd-com/urlcode/pull/59) or an approved successor; the version number `0.3.0` alone is insufficient. Use an exact reviewed core commit and clean committed source trees.

```sh
node scripts/pack-sources.mjs \
  --core /absolute/source/urlcode \
  --auth /absolute/source/urlcode-auth \
  --admin /absolute/source/urlcode-admin \
  --core-revision REVIEWED_40_CHARACTER_COMMIT_SHA \
  --out /absolute/new-private-package-directory
```

The helper runs lockfile installation without lifecycle scripts, installs unpublished peers from local tarballs, typechecks/builds, packs and records commit/integrity metadata. Nothing is published. `--offline` requires an existing dependency cache; `--skip-install` reuses third-party dependencies. Neither bypasses the reviewed revision/clean-tree requirement. Run each repository's full `npm run verify` separately.

Install the three resulting tarballs together in your operator directory, using filenames recorded in `source-manifest.json`. Follow auth's scaffold/bootstrap procedure first. The current auth scaffold creates auth only; add admin explicitly to reviewed route YAML and the external host.

## Wiring

Declare the additional logical extension and its exclusive mount:

```yaml
extensions:
  admin:
    version: '1'
    config: {}
routes:
  /admin/*:
    extension: admin
    methods: [GET, HEAD, POST]
```

Merge these entries into the existing versioned auth project, then review and update the static project revision pin. In the trusted external host:

```js
import {authExtension} from '@jimhoyd/urlcode-auth';
import {adminExtension} from '@jimhoyd/urlcode-admin';

// service, csrfKey and reviewed projectSha256 are operator-owned values.
export default {
  extensions: [
    authExtension({service, csrfKey, projectSha256}),
    adminExtension({service, csrfKey, projectSha256, authMount: '/account'}),
  ],
  async close() { await service.close(); },
};
```

The snippet is an integration fragment; use the auth scaffold's private key/service setup and required HTTPS origin rather than inventing credentials. Use the same CSRF key and shared service. No auth package is loaded from application YAML. Runtime activation uses the explicit external host and matching canonical `--origin`.

Administrative actions authenticate internally even without an extra route policy. Missing sessions or administrative permissions receive 404 at the console gate. Use operator role declarations with the actual permissions exported by this implementation: `auth.users.read`, `auth.users.manage`, `auth.users.create`, `auth.sessions.manage`, `auth.roles.read`, `auth.audit.read`, `auth.cases.read`, `auth.cases.manage`, and `auth.users.impersonate`. `*` grants full operator-defined administrator permissions. Do not copy the proposal's separate `admin.*` permission names and expect them to work automatically.

## Operating the console

Bootstrap the first administrator through auth's operator CLI using JSON stdin. Writes require recent authentication and a reason; role/status/session changes run through the auth service's transactional authority checks. Roles themselves remain operator configuration. Masked lists, pagination, permission-filtered navigation and audit records help limit routine exposure.

Cases currently model bounded, two-person approval of specific administrative changes with target-version checks. They are not a complete lost-everything identity-verification process. Establish an operator evidence procedure before using factor-reset cases. The console does not supply all proposed notes, close/reject, requester evidence or reporting workflows.

Impersonation requires explicit service opt-in, a dedicated permission and a `notifyImpersonation` callback. If the required notification fails, the issued session is revoked before returning it. Impersonation expires and cannot perform fresh account-security/admin changes. The account page shows a warning; arbitrary guest application pages do not automatically show a banner. Ending impersonation requires signing back in as the operator.

Optional presentation and invitation/notification callbacks are operator-owned integrations. No real SES, Google or Apple account is provisioned by this package. Keep keys and database backups outside the application project, retain matching configuration, and close the shared service only once after both extensions stop.

Apache-2.0. The package remains private; packing does not publish it.

## New local installation

After installing the reviewed local packages, run `urlcode-admin init --directory /absolute/new/site`. It creates a private operator host and database key directory outside the route project, with registration off and auth/admin mounts configured. Follow the generated README to bootstrap the first administrator, configure HTTPS and approve the project revision. This does not deploy or send mail.

## Private dependency CI

The manual verification workflow checks out exact core/auth revisions and runs Node 22/24/26. Automatic PR triggers are pending an organization-approved read-only auth repository credential in `URLCODE_AUTH_READ_TOKEN`; deploy keys are disabled by repository policy. Do not reuse a broad personal token or weaken that policy. After approved credential provisioning, run the workflow and enable PR/main triggers. Local full verification and source-package smoke tests remain usable without this credential.
