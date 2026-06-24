export const onRequestPost = async (context: any) => {
  try {
    const body = await context.request.json();
    
    return new Response(JSON.stringify({ 
      success: true, 
      message: 'API is working',
      received: body 
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error: any) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};