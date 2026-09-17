import {AuthHttpError} from '@jimhoyd/urlcode-auth';
import type {AuthService,AuthUser} from '@jimhoyd/urlcode-auth';

export function maskEmail(email:string):string {const at=email.lastIndexOf('@');return at<1?'***':email[0]+'***'+email.slice(at);}
/** Every field is quoted; spreadsheet formula triggers are made literal text. */
export function csvCell(value:unknown):string {
 const text=String(value??''),safe=/^[\s\uFEFF]*[=+\-@]/u.test(text)||/^[\t\r\n]/u.test(text)?"'"+text:text;
 return '"'+safe.replaceAll('"','""')+'"';
}
export function usersCsv(users:readonly AuthUser[]):Uint8Array {
 if(users.length>50)throw new AuthHttpError(400,'Export exceeds one page');
 const rows:unknown[][]=[['id','email_masked','status','roles','created_utc','email_verified','display_name','locale'],...users.map(user=>[user.id,maskEmail(user.email),user.status,user.roles.join(';'),new Date(user.created).toISOString(),user.emailVerified,user.profile?.displayName??'',user.profile?.locale??''])];
 return new TextEncoder().encode(rows.map(row=>row.map(csvCell).join(',')).join('\r\n')+'\r\n');
}
function one(values:URLSearchParams,key:string):string|undefined {const found=values.getAll(key);if(found.length>1)throw new AuthHttpError(400,'Duplicate filter');return found[0]||undefined;}
export function userFilters(values:URLSearchParams):NonNullable<Parameters<AuthService['listUsers']>[0]> {
 const status=one(values,'status'),query=one(values,'query'),role=one(values,'role'),after=one(values,'after');
 if(status&&!['active','locked','pending-delete'].includes(status))throw new AuthHttpError(400,'Invalid status');
 return {limit:50,...(status?{status:status as AuthUser['status']}:{}),...(query?{query}:{}),...(role?{role}:{}),...(after?{after}:{})};
}
export function auditFilters(values:URLSearchParams):NonNullable<Parameters<AuthService['listAudit']>[0]> {
 const result:NonNullable<Parameters<AuthService['listAudit']>[0]>={limit:50};
 for(const name of ['actor','subject','action','after'] as const){const value=one(values,name);if(value)result[name]=value;}
 for(const name of ['from','to'] as const){const value=one(values,name);if(value){if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?Z$/.test(value))throw new AuthHttpError(400,'Use a UTC date and time ending in Z');const time=Date.parse(value);if(!Number.isSafeInteger(time)||time<0||new Date(time).toISOString().replace('.000Z','Z')!==(value.length===17?value.slice(0,-1)+':00Z':value))throw new AuthHttpError(400,'Invalid audit time');result[name]=time;}}
 if(result.from!==undefined&&result.to!==undefined&&result.from>result.to)throw new AuthHttpError(400,'Invalid time range');return result;
}
export function nextPage(path:string,query:URLSearchParams,after:string,allowed:readonly string[]):string {const result=new URLSearchParams();for(const name of allowed){const value=one(query,name);if(value)result.set(name,value);}result.set('after',after);return path+'?'+result.toString();}
export function selectedNames(body:Uint8Array,contentType:string|null):string[] {
 if(body.byteLength>16384)throw new AuthHttpError(413,'Request body too large');
 let source:string;try{source=new TextDecoder('utf-8',{fatal:true}).decode(body);}catch{throw new AuthHttpError(400,'Invalid encoding');}
 let names:string[];if(contentType?.split(';')[0]?.trim()==='application/json'){try{const parsed:unknown=JSON.parse(source);names=parsed&&typeof parsed==='object'&&!Array.isArray(parsed)?Object.keys(parsed):[];}catch{throw new AuthHttpError(400,'Invalid JSON');}}
 else names=[...new URLSearchParams(source).keys()];
 return names.filter(name=>/^selected\.[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(name));
}
export function selectedAccounts(fields:Record<string,string>):string[] {
 const ids=Object.entries(fields).filter(([name])=>name.startsWith('selected.')).map(([name,value])=>{if(value!=='yes')throw new AuthHttpError(400,'Invalid selection');return name.slice(9);});
 if(fields.accountIds){if(ids.length)throw new AuthHttpError(400,'Use one selection format');ids.push(...fields.accountIds.split(',').map(value=>value.trim()).filter(Boolean));}
 if(!ids.length||ids.length>50||new Set(ids).size!==ids.length)throw new AuthHttpError(400,'Select between one and fifty distinct accounts');return ids;
}
