import {escapeHtml} from '@jimhoyd/urlcode-ui';
import {pageResponse} from '@jimhoyd/urlcode-auth';

/** Trusted admin composition only; the reusable UI package has no knowledge of this shell. */
export function adminPage(...args:Parameters<typeof pageResponse>):ReturnType<typeof pageResponse> {
 const [title,content,status,headers,script,presentation]=args;
 const boundary=content.startsWith('<aside class="ui-sidebar"')?content.indexOf('</aside>')+8:0;
 if(!boundary)return pageResponse(...args);
 const label=escapeHtml(presentation?.textSource(title)??title);
 const body=`<div class="ui-shell">${content.slice(0,boundary)}<div class="ui-content"><header class="ui-page-header"><div><p class="ui-muted">URLCode / ${escapeHtml(presentation?.text('page.admin')??'Administration')}</p><h2>${label}</h2></div></header>${content.slice(boundary)}</div></div>`;
 return pageResponse(title,body,status,headers,script,presentation);
}
