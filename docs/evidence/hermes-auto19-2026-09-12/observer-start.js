async page => {
  if (page.__auto19Audit) throw new Error('observer_already_started');
  page.__auto19Audit = [];
  page.on('request', request => {
    if (request.method() !== 'POST' || !request.url().startsWith('http://127.0.0.1:18975/api/')) return;
    let body = null; try {body = request.postDataJSON();} catch {}
    page.__auto19Audit.push({at: Date.now(), method: request.method(), path: request.url().replace('http://127.0.0.1:18975',''), body});
  });
  return {observing: true, time: Date.now()};
}
