const form = document.querySelector('form');
form.addEventListener('submit', loginUser);

async function loginUser(event) {
  event.preventDefault();
  const username = document.querySelector('#username').value;
  const password = document.querySelector('#password').value;
  const response = await fetch('/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ username, password })
  });
  if (response.ok) {
    const token = await response.json();
    localStorage.setItem('token', token.access_token);
    window.location.href = '/dashboard';
  } else {
    alert('Incorrect username or password');
  }
}
