// Local development only. On Vercel, api/index.js is used instead.
const app=require('./app'),port=process.env.PORT||3000;
app.db().then(()=>app.listen(port,()=>console.log('ZT Visitor running on http://localhost:'+port)))
 .catch(e=>{console.error('Could not start:',e.message);process.exit(1)});
