# Admin implementation status

The first-release spike is not fully complete. Cross-repository acceptance: https://github.com/jimhoyd-com/urlcode/issues/58. Core extension integration: PR #59. Auth owns identities, sessions and transactional authority checks; this package owns the trusted administration interface.

Implemented: scoped internal authorization; no impersonated admin access; fresh, reasoned mutations; account listing/filtering/details/setup invitation/export; lock/unlock/role assignment; global and individual session revocation; role definitions; audit pagination; registration approval; dual-approval security cases with notes/closure; opt-in short-lived impersonation with required notice; shared safe presentation; auth/admin initialization with private operator storage.

## Remaining first-release acceptance

- Connect live operator runtime/provider/sender observations to the implemented bounded, permission-gated health adapter. Thirty-day activity tables use bounded aggregate counters; data begins when the feature is activated.
- Complete search/sort filters, whole-result exports and bulk role/verification workflows. Current filtered exports are bounded to 50 masked records with audit; lock/unlock/revoke bulk operations are atomic and require typed confirmation.
- Full detail/recovery/contact/terms/activity tabs and audited reveal, administrative email verification/reset/deletion workflows.
- Complete lost-everything recovery intake and evidence review; current maker/checker cases are security actions, not identity verification.
- Email template localization and manual browser/accessibility evidence. Auth/admin semantic UI copy is localizable; no complete non-English catalogue is bundled.
- An application-wide impersonation warning/integration contract. The trusted account page warns, but arbitrary guest pages do not acquire a universal banner. Impersonation stays explicitly disabled unless the operator opts in.
- Cross-package packed-install and CI evidence at final commits, plus deployment/recovery/security review.

Role definitions remain reviewed operator configuration. User role assignments are administrative transactions. This preserves the separation between changing authority definitions and assigning already-reviewed authority.
