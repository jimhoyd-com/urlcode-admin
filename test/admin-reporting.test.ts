import test from 'node:test';
import assert from 'node:assert/strict';
import {auditFilters,csvCell,nextPage,selectedAccounts,selectedNames,usersCsv} from '../src/admin-reporting.ts';

test('CSV cells quote delimiters and neutralize spreadsheet formulas including leading whitespace',()=>{
 for(const value of ['=SUM(1,2)',' +1','-1','@name','\tcommand','\rcommand','\ncommand','\uFEFF=1'])assert.ok(csvCell(value).startsWith('"\''));
 assert.equal(csvCell('a,"b"\nc'),'"a,""b""\nc"');
 assert.throws(()=>usersCsv(Array.from({length:51},()=>({id:'id',email:'x@example.test',status:'active' as const,roles:[],created:0,emailVerified:false,totpEnabled:false}))));
});
test('audit filters reject ambiguous or invalid dates and pagination preserves active filters',()=>{
 assert.deepEqual(auditFilters(new URLSearchParams('action=session.login&from=2026-09-01T00%3A00Z&to=2026-09-02T00%3A00Z')),{limit:50,action:'session.login',from:Date.parse('2026-09-01T00:00Z'),to:Date.parse('2026-09-02T00:00Z')});
 for(const query of ['from=2026-02-30T00%3A00Z','from=bad','action=a&action=b','from=2026-09-02T00%3A00Z&to=2026-09-01T00%3A00Z'])assert.throws(()=>auditFilters(new URLSearchParams(query)));
 assert.equal(nextPage('/admin/users',new URLSearchParams('query=a%40b&role=member&ignored=bad'),'cursor',['query','role']),'/admin/users?query=a%40b&role=member&after=cursor');
});
test('native checkbox selection is bounded, unambiguous and rejects duplicate bulk IDs',()=>{
 const id='12345678-1234-1234-1234-123456789abc';assert.deepEqual(selectedNames(Buffer.from('selected.'+id+'=yes'),'application/x-www-form-urlencoded'),['selected.'+id]);assert.deepEqual(selectedAccounts({['selected.'+id]:'yes'}),[id]);
 assert.throws(()=>selectedAccounts({accountIds:id+','+id}));assert.throws(()=>selectedAccounts({accountIds:id,['selected.'+id]:'yes'}));assert.throws(()=>selectedAccounts({}));assert.throws(()=>selectedAccounts({accountIds:Array.from({length:51},(_,i)=>String(i)).join(',')}));
});
