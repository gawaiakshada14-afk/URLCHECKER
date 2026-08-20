require('dotenv').config();

let key = process.env.OPENROUTER_API_KEY || '';
if (!key.startsWith('sk-or-v1-')) {
  key = 'sk-or-v1-' + key;
}

async function testOpenRouter() {
  console.log('Testing OpenRouter request with formatted key...');

  try {
    const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${key.trim()}`,
        'HTTP-Referer': 'https://shieldurl.io',
        'X-Title': 'ShieldURL AI Security Analyst',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'meta-llama/llama-3.3-70b-instruct:free',
        messages: [{ role: 'user', content: 'Say hello in 5 words.' }]
      })
    });

    console.log('Status:', res.status, res.statusText);
    const text = await res.text();
    console.log('Body:', text);
  } catch (e) {
    console.error('Error:', e);
  }
}

testOpenRouter();
