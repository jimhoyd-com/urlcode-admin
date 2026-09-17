import type { RuntimeExtension, ExtensionRequest } from '@jimhoyd/urlcode/extensions';
import type { AuthService, AuthPrincipal, Presentation } from '@jimhoyd/urlcode-auth';
import { AuthHttp, AuthHttpError, csrfField, escapeHtml, formField as baseField, httpFailure, jsonResponse, pageResponse as renderPage, readFields, wantsJson, hasPermission } from '@jimhoyd/urlcode-auth';
export interface AdminExtensionOptions {
    presentation?: Presentation;
    service: AuthService;
    csrfKey: Uint8Array;
    projectSha256: string;
    authMount?: string;
    notifyImpersonation?: (message: {
        email: string;
        actorId: string;
        reason: string;
        signal: AbortSignal;
    }) => Promise<void>;
    sendSetup?: (message: {
        email: string;
        token: string;
        signal: AbortSignal;
    }) => Promise<void>;
    sendInvitation?: (message: {
        email: string;
        token: string;
        signal: AbortSignal;
    }) => Promise<void>;
}
const schema = { type: 'object', additionalProperties: false, properties: {} };
const permissions = ['auth.cases.read', 'auth.cases.manage', 'auth.users.impersonate', 'auth.users.export', 'auth.users.create', 'auth.users.read', 'auth.users.manage', 'auth.audit.read', 'auth.sessions.manage', 'auth.roles.read'];
function masked(email: string): string { const at = email.lastIndexOf('@'); return at < 1 ? '***' : email[0] + '***' + email.slice(at); }
function renderForm(action: string, csrf: string, fields: string, label: string): string { return `<form method="post" action="${escapeHtml(action)}">${csrfField(csrf)}${fields}<button type="submit">${escapeHtml(label)}</button></form>`; }
const form = renderForm, formField = baseField;
export function adminExtension(options: AdminExtensionOptions): RuntimeExtension {
    const authMount = options.authMount || '/account';
    if (!/^\/[A-Za-z0-9/_-]*$/.test(authMount) || authMount.includes('//'))
        throw new Error('Invalid auth mount');
    return { name: 'admin', version: '1', projectSha256: options.projectSha256, targets: ['node'], schema, credentialHeaders: ['cookie', 'authorization', 'x-csrf-token'],
        activate(_config, context) {
            if (context.mounts.length !== 1)
                throw new Error('Admin requires exactly one mount');
            const mount = context.mounts[0]!, http = new AuthHttp({ origin: context.origin, csrfKey: options.csrfKey }), service = options.service;
            function requirePermission(principal: AuthPrincipal, permission: string): void { if (!hasPermission(principal, permission))
                throw new AuthHttpError(403, 'Permission required'); }
            function navigation(principal: AuthPrincipal, text: (source: string) => string = source => source): string { return `<nav aria-label="Administration"><a href="${escapeHtml(mount)}">Overview</a>${[['cases', 'Cases', 'auth.cases.read'], ['users', 'Users', 'auth.users.read'], ['registrations', 'Registration', 'auth.users.manage'], ['roles', 'Roles', 'auth.roles.read'], ['sessions', 'Sessions', 'auth.sessions.manage'], ['audit', 'Audit', 'auth.audit.read']].filter(([_path, _label, permission]) => hasPermission(principal, permission!)).map(([path, label]) => `<a href="${escapeHtml(mount + '/' + path)}">${escapeHtml(text(label!))}</a>`).join('')}<a href="${escapeHtml(authMount + '/step-up')}">Confirm identity</a></nav>`; }
            return { async handle(request: ExtensionRequest) {
                    const presentation = options.presentation?.resolve({ ...(request.query.get('lang') ? { queryLocale: request.query.get('lang')! } : {}), ...(request.headers.get('accept-language') ? { acceptLanguage: request.headers.get('accept-language')! } : {}) });
                    const pageResponse = (...args: Parameters<typeof renderPage>) => renderPage(...[args[0], args[1], args[2], args[3], args[4], presentation] as Parameters<typeof renderPage>);
                    const formField = (name: string, label: string, type = 'text', autocomplete = 'off', required = true) => baseField(name, presentation?.textSource(label) ?? label, type, autocomplete, required);
                    const form = (action: string, csrf: string, fields: string, button: string) => renderForm(action, csrf, fields, presentation?.textSource(button) ?? button);
                    try {
                        const token = http.session(request), principal = token ? await service.authenticate(token) : null;
                        if (!token || !principal || principal.impersonatorId || !permissions.some(permission => hasPermission(principal, permission)))
                            throw new AuthHttpError(404, 'Not found');
                        const path = request.path.slice(mount.length) || '/';
                        if (!['GET', 'HEAD', 'POST'].includes(request.method))
                            return jsonResponse(405, { error: 'Method not allowed' }, [['allow', 'GET, HEAD, POST']]);
                        const csrf = http.token(token), nav = navigation(principal, source => presentation?.textSource(source) ?? source);
                        if (request.method !== 'POST') {
                            if (path === '/' || path === '/dashboard') {
                                const granted = permissions.filter(permission => hasPermission(principal, permission));
                                const stats = hasPermission(principal, 'auth.users.read') ? await service.dashboard() : undefined;
                                const users = hasPermission(principal, 'auth.users.read') ? await service.listUsers({ limit: 50 }) : undefined;
                                const recent = hasPermission(principal, 'auth.audit.read') ? await service.listAudit({ limit: 10 }) : undefined;
                                return wantsJson(request) ? jsonResponse(200, { permissions: granted, csrf, ...(users ? { accounts: stats, accountsShown: users.users.length, moreAccounts: !!users.next } : {}), ...(recent ? { recentEvents: recent.events } : {}) }) : pageResponse('Administration', nav + (hasPermission(principal, 'auth.users.impersonate') && options.notifyImpersonation ? form(mount + '/impersonate', csrf, formField('accountId', 'Account ID') + formField('reason', 'Reason'), 'Start ten-minute support impersonation') : '') + '<p>Select a section. Only permitted operations are shown. Configuration remains in version-controlled project files.</p>' + (users ? `<p>${stats?.users} accounts; ${stats?.locked} locked; ${stats?.pendingDeletion} pending deletion; ${stats?.sessions} sessions; ${stats?.waitlist} waiting for approval.</p>` : '') + (recent ? `<h2>Recent events</h2><ul>${recent.events.map(event => `<li>${escapeHtml(event.action)} — ${escapeHtml(new Date(event.created).toISOString())}</li>`).join('')}</ul>` : ''));
                            }
                            if (path === '/cases') {
                                requirePermission(principal, 'auth.cases.read');
                                const result = await service.listCases({ limit: 50, ...(request.query.get('after') ? { after: request.query.get('after')! } : {}) });
                                if (wantsJson(request))
                                    return jsonResponse(200, { ...result, csrf });
                                return pageResponse('Support cases', nav + `<ul>${result.cases.map(item => `<li>${escapeHtml(item.action)} for ${escapeHtml(item.accountId)} — ${escapeHtml(item.status)}<p>${escapeHtml(item.reason)}</p><ul>${(item.notes ?? []).map(note => `<li>${escapeHtml(note.actorId)}: ${escapeHtml(note.note)}</li>`).join('')}</ul>${hasPermission(principal, 'auth.cases.manage') ? form(mount + '/cases/note', csrf, `<input type="hidden" name="caseId" value="${escapeHtml(item.id)}">` + formField('reason', 'Case note'), 'Add note') + (item.status === 'pending' ? form(mount + '/cases/close', csrf, `<input type="hidden" name="caseId" value="${escapeHtml(item.id)}">` + formField('reason', 'Closure reason'), 'Close without applying') : '') : ''}${item.status === 'pending' && item.makerId !== principal.id && hasPermission(principal, 'auth.cases.manage') ? form(mount + '/cases/approve', csrf, `<input type="hidden" name="caseId" value="${escapeHtml(item.id)}">` + formField('reason', 'Approval reason'), 'Approve and apply') : ''}</li>`).join('')}</ul>` + (hasPermission(principal, 'auth.cases.manage') ? form(mount + '/cases/create', csrf, formField('accountId', 'Account ID') + formField('action', 'Action: reset-factors, lock, unlock or roles') + formField('roles', 'Roles (for roles action)', 'text', 'off', false) + formField('reason', 'Reason'), 'Create case for a second administrator') : '') + (result.next ? `<a href="${escapeHtml(mount + '/cases?after=' + encodeURIComponent(result.next))}">Next page</a>` : ''));
                            }
                            if (path === '/registrations') {
                                requirePermission(principal, 'auth.users.manage');
                                const result = await service.listRegistrationRequests({ limit: 50, ...(request.query.get('after') ? { after: request.query.get('after')! } : {}) });
                                if (wantsJson(request))
                                    return jsonResponse(200, { ...result, requests: result.requests.map(item => ({ ...item, email: masked(item.email) })), csrf });
                                return pageResponse('Registration requests', nav + `<ul>${result.requests.map(item => `<li>${escapeHtml(masked(item.email))}${form(mount + '/registrations/approve', csrf, `<input type="hidden" name="requestId" value="${escapeHtml(item.id)}">` + formField('reason', 'Reason'), 'Approve account')}</li>`).join('')}</ul>` + (result.next ? `<a href="${escapeHtml(mount + '/registrations?after=' + encodeURIComponent(result.next))}">Next page</a>` : '') + (options.sendInvitation && hasPermission(principal, 'auth.users.create') ? form(mount + '/invitations', csrf, formField('email', 'Email address', 'email') + formField('reason', 'Reason'), 'Send invitation') : ''));
                            }
                            if (path === '/users/detail') {
                                requirePermission(principal, 'auth.users.read');
                                const account = await service.getUser(request.query.get('id') || '');
                                if (!account)
                                    throw new AuthHttpError(404, 'Account not found');
                                const user = { ...account, email: masked(account.email) }, sessions = hasPermission(principal, 'auth.sessions.manage') ? await service.listSessions(user.id) : undefined;
                                if (wantsJson(request))
                                    return jsonResponse(200, { user, ...(sessions ? { sessions } : {}), csrf });
                                return pageResponse('Account details', nav + `<dl><dt>Account ID</dt><dd>${escapeHtml(user.id)}</dd><dt>Email</dt><dd>${escapeHtml(user.email)}</dd><dt>Status</dt><dd>${escapeHtml(user.status)}</dd><dt>Email verified</dt><dd>${user.emailVerified ? 'Yes' : 'No'}</dd><dt>Authenticator enabled</dt><dd>${user.totpEnabled ? 'Yes' : 'No'}</dd><dt>Roles</dt><dd>${escapeHtml(user.roles.join(', '))}</dd></dl>` + (sessions ? `<p>${sessions.length} sessions.</p>` : '') + (hasPermission(principal, 'auth.users.export') ? form(mount + '/users/export', csrf, `<input type="hidden" name="accountId" value="${escapeHtml(user.id)}">` + formField('reason', 'Reason'), 'Export account data') : ''));
                            }
                            if (path === '/users') {
                                requirePermission(principal, 'auth.users.read');
                                const after = request.query.get('after') || undefined;
                                const status = request.query.get('status');
                                if (status && !['active', 'locked', 'pending-delete'].includes(status))
                                    throw new AuthHttpError(400, 'Invalid status');
                                const result = await service.listUsers({ limit: 50, ...(after ? { after } : {}), ...(request.query.get('query') ? { query: request.query.get('query')! } : {}), ...(request.query.get('role') ? { role: request.query.get('role')! } : {}), ...(status ? { status: status as 'active' | 'locked' | 'pending-delete' } : {}) }), users = result.users.map(user => ({ ...user, email: masked(user.email) }));
                                if (wantsJson(request))
                                    return jsonResponse(200, { users, ...(result.next ? { next: result.next } : {}), csrf });
                                return pageResponse('Users', nav + (options.sendSetup && hasPermission(principal, 'auth.users.create') ? form(mount + '/users/create', csrf, formField('email', 'Email address', 'email') + formField('reason', 'Reason'), 'Create account and send setup link') : '') + `<form method="get" action="${escapeHtml(mount + '/users')}">${formField('query', 'Email contains', 'text', 'off', false)}${formField('role', 'Role name', 'text', 'off', false)}${formField('status', 'Status: active, locked or pending-delete', 'text', 'off', false)}<button>Filter users</button></form>` + `<table><caption>Accounts (email addresses masked)</caption><thead><tr><th scope="col">Account</th><th scope="col">Status</th><th scope="col">Roles</th><th scope="col">Actions</th></tr></thead><tbody>${users.map(user => `<tr><td><a href="${escapeHtml(mount + '/users/detail?id=' + encodeURIComponent(user.id))}">${escapeHtml(user.email)}</a><br><code>${escapeHtml(user.id)}</code></td><td>${escapeHtml(user.status)}</td><td>${escapeHtml(user.roles.join(', '))}</td><td>${hasPermission(principal, 'auth.users.manage') && user.id !== principal.id && user.status !== 'pending-delete' ? form(mount + '/users/status', csrf, `<input type="hidden" name="accountId" value="${escapeHtml(user.id)}"><input type="hidden" name="status" value="${user.status === 'active' ? 'locked' : 'active'}">` + formField('reason', 'Reason'), user.status === 'active' ? 'Lock account' : 'Unlock account') : ''}</td></tr>`).join('')}</tbody></table>${result.next ? `<a href="${escapeHtml(mount + '/users?after=' + encodeURIComponent(result.next))}">Next page</a>` : ''}`);
                            }
                            if (path === '/roles') {
                                requirePermission(principal, 'auth.roles.read');
                                const roles = service.getRoles();
                                if (wantsJson(request))
                                    return jsonResponse(200, { roles, csrf });
                                return pageResponse('Roles', nav + `<p>Role definitions are read-only here.</p><dl>${Object.entries(roles).map(([name, grants]) => `<dt>${escapeHtml(name)}</dt><dd>${escapeHtml(grants.join(', '))}</dd>`).join('')}</dl>` + (hasPermission(principal, 'auth.users.manage') ? form(mount + '/users/roles', csrf, formField('accountId', 'Account ID') + formField('roles', 'Role names separated by commas') + formField('reason', 'Reason'), 'Assign roles') : ''));
                            }
                            if (path === '/sessions') {
                                requirePermission(principal, 'auth.sessions.manage');
                                const accountId = request.query.get('accountId');
                                const result = accountId ? { sessions: await service.listSessions(accountId), next: undefined } : await service.listAllSessions({ limit: 50, ...(request.query.get('after') ? { after: request.query.get('after')! } : {}) });
                                if (wantsJson(request))
                                    return jsonResponse(200, { ...result, sessions: result.sessions.map(session => ({ ...session, ...('email' in session ? { email: masked(String(session.email)) } : {}) })), csrf });
                                return pageResponse('Sessions', nav + `<form method="get" action="${escapeHtml(mount + '/sessions')}">${formField('accountId', 'Account ID', 'text', 'off', false)}<button type="submit">Find sessions</button></form><p>${result.sessions.length} sessions on this page.</p><ul>${result.sessions.map(session => `<li>Account ${escapeHtml('accountId' in session ? session.accountId : accountId)}; started ${escapeHtml(new Date(session.created).toISOString())}; expires ${escapeHtml(new Date(session.expires).toISOString())}${form(mount + '/sessions/revoke-one', csrf, `<input type="hidden" name="sessionId" value="${escapeHtml(session.id)}">` + formField('reason', 'Reason'), 'Revoke this session')}</li>`).join('')}</ul>` + (result.next ? `<a href="${escapeHtml(mount + '/sessions?after=' + encodeURIComponent(result.next))}">Next page</a>` : '') + (accountId ? form(mount + '/sessions/revoke', csrf, `<input type="hidden" name="accountId" value="${escapeHtml(accountId)}">` + formField('reason', 'Reason'), 'Revoke all sessions') : ''));
                            }
                            if (path === '/audit') {
                                requirePermission(principal, 'auth.audit.read');
                                const after = request.query.get('after') || undefined, result = await service.listAudit({ limit: 50, ...(after ? { after } : {}) });
                                if (wantsJson(request))
                                    return jsonResponse(200, result);
                                return pageResponse('Audit', nav + `<table><caption>Recent security events</caption><thead><tr><th scope="col">Time</th><th scope="col">Action</th><th scope="col">Actor</th><th scope="col">Subject</th></tr></thead><tbody>${result.events.map(event => `<tr><td>${escapeHtml(new Date(event.created).toISOString())}</td><td>${escapeHtml(event.action)}</td><td>${escapeHtml(event.actor)}</td><td>${escapeHtml(event.subject)}</td></tr>`).join('')}</tbody></table>${result.next ? `<a href="${escapeHtml(mount + '/audit?after=' + encodeURIComponent(result.next))}">Next page</a>` : ''}`);
                            }
                            throw new AuthHttpError(404, 'Not found');
                        }
                        const fields = readFields(request, ['accountId', 'roles', 'status', 'reason', 'requestId', 'email', 'action', 'caseId', 'sessionId']);
                        http.verify(request, fields);
                        if (!fields.reason?.trim() || fields.reason.length > 256)
                            throw new AuthHttpError(400, 'A reason is required');
                        if (Date.now() - principal.authenticatedAt > 5 * 60 * 1000)
                            throw new AuthHttpError(403, 'Confirm your identity before this action');
                        if (path === '/users/export') {
                            requirePermission(principal, 'auth.users.export');
                            return jsonResponse(200, await service.adminExport({ actorToken: token, accountId: fields.accountId || '', reason: fields.reason }), [['content-disposition', 'attachment; filename="account-export.json"']]);
                        }
                        else if (path === '/users/create') {
                            requirePermission(principal, 'auth.users.create');
                            if (!options.sendSetup)
                                throw new AuthHttpError(503, 'Setup delivery unavailable');
                            const created = await service.adminCreateUser({ actorToken: token, email: fields.email || '', reason: fields.reason });
                            const controller = new AbortController();
                            let timer: ReturnType<typeof setTimeout> | undefined;
                            try {
                                await Promise.race([options.sendSetup({ email: created.user.email, token: created.setupToken, signal: controller.signal }), new Promise<void>((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new Error('Setup delivery timeout')); }, 5000); })]);
                            }
                            finally {
                                if (timer)
                                    clearTimeout(timer);
                            }
                        }
                        else if (path === '/sessions/revoke-one') {
                            requirePermission(principal, 'auth.sessions.manage');
                            await service.adminRevokeSession({ actorToken: token, sessionId: fields.sessionId || '', reason: fields.reason });
                        }
                        else if (path === '/cases/create') {
                            requirePermission(principal, 'auth.cases.manage');
                            if (!['reset-factors', 'lock', 'unlock', 'roles'].includes(fields.action || ''))
                                throw new AuthHttpError(400, 'Invalid case action');
                            await service.createCase({ actorToken: token, accountId: fields.accountId || '', action: fields.action as 'reset-factors' | 'lock' | 'unlock' | 'roles', ...(fields.roles ? { roles: fields.roles.split(',').map(role => role.trim()).filter(Boolean) } : {}), reason: fields.reason });
                        }
                        else if (path === '/cases/note') {
                            requirePermission(principal, 'auth.cases.manage');
                            await service.addCaseNote({ actorToken: token, caseId: fields.caseId || '', note: fields.reason });
                        }
                        else if (path === '/cases/close') {
                            requirePermission(principal, 'auth.cases.manage');
                            await service.closeCase({ actorToken: token, caseId: fields.caseId || '', reason: fields.reason });
                        }
                        else if (path === '/cases/approve') {
                            requirePermission(principal, 'auth.cases.manage');
                            await service.approveCase({ actorToken: token, caseId: fields.caseId || '', reason: fields.reason });
                        }
                        else if (path === '/impersonate') {
                            requirePermission(principal, 'auth.users.impersonate');
                            if (!options.notifyImpersonation)
                                throw new AuthHttpError(503, 'Impersonation notification is required');
                            const result = await service.createImpersonation({ actorToken: token, accountId: fields.accountId || '', reason: fields.reason });
                            const controller = new AbortController();
                            let timer: ReturnType<typeof setTimeout> | undefined;
                            try {
                                await Promise.race([options.notifyImpersonation({ email: result.user.email, actorId: principal.id, reason: fields.reason, signal: controller.signal }), new Promise<void>((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new Error('Notification timeout')); }, 5000); })]);
                            }
                            catch (error) {
                                await service.logout(result.token);
                                throw error;
                            }
                            finally {
                                if (timer)
                                    clearTimeout(timer);
                            }
                            return jsonResponse(303, { impersonating: true }, [['location', authMount + '/account'], ...http.sessionHeaders(result.token)]);
                        }
                        else if (path === '/registrations/approve') {
                            requirePermission(principal, 'auth.users.manage');
                            await service.approveRegistration({ actorToken: token, requestId: fields.requestId || '', reason: fields.reason });
                        }
                        else if (path === '/invitations') {
                            requirePermission(principal, 'auth.users.create');
                            if (!options.sendInvitation)
                                throw new AuthHttpError(503, 'Invitation delivery unavailable');
                            const issued = await service.invite({ actorToken: token, email: fields.email || '' });
                            const controller = new AbortController();
                            let timer: ReturnType<typeof setTimeout> | undefined;
                            try {
                                await Promise.race([options.sendInvitation({ email: fields.email || '', token: issued.token, signal: controller.signal }), new Promise<void>((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new Error('Delivery timeout')); }, 5000); })]);
                            }
                            finally {
                                if (timer)
                                    clearTimeout(timer);
                            }
                        }
                        else if (path === '/users/roles') {
                            requirePermission(principal, 'auth.users.manage');
                            const roles = (fields.roles || '').split(',').map(role => role.trim()).filter(Boolean);
                            await service.adminSetRoles({ actorToken: token, accountId: fields.accountId || '', roles, reason: fields.reason });
                        }
                        else if (path === '/users/status') {
                            requirePermission(principal, 'auth.users.manage');
                            if (fields.status !== 'active' && fields.status !== 'locked')
                                throw new AuthHttpError(400, 'Invalid status');
                            await service.adminSetStatus({ actorToken: token, accountId: fields.accountId || '', status: fields.status, reason: fields.reason });
                        }
                        else if (path === '/sessions/revoke') {
                            requirePermission(principal, 'auth.sessions.manage');
                            await service.adminRevokeSessions({ actorToken: token, accountId: fields.accountId || '', reason: fields.reason });
                        }
                        else
                            throw new AuthHttpError(404, 'Not found');
                        return wantsJson(request) ? jsonResponse(200, { updated: true }) : pageResponse('Update completed', nav + '<p>The operation completed.</p>');
                    }
                    catch (error) {
                        return httpFailure(error, request, presentation);
                    }
                } };
        } };
}
