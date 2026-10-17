const BASE = 'http://localhost:4001';
function getUsers() { return fetch(BASE + '/api/users').then(r => r.json()); }
function getUser(id) { return fetch(BASE + '/api/users/' + id, { method: 'DELETE', headers: { Authorization: 'Bearer x' } }); }
