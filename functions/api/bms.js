export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');
  
  const debug = {
    method: request.method,
    action: action,
    action_type: typeof action,
    action_len: action ? action.length : 0,
    url: request.url,
    has_update_check: action === 'update',
    has_post_check: request.method === 'POST'
  };
  
  return new Response(JSON.stringify(debug, null, 2), {
    headers: { 
      'Content-Type': 'application/json', 
      'Access-Control-Allow-Origin': '*' 
    }
  });
}
