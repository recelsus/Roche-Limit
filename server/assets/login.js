const form = document.getElementById('login-form');
const message = document.getElementById('message');

function loginTargetUrl() {
  return form.getAttribute('action') || window.location.href;
}

function successRedirectUrl() {
  const path = window.location.pathname.replace(/\/login\/?$/, '/');
  return path === '' ? '/' : path;
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  message.textContent = '';
  message.dataset.state = '';

  const body = new URLSearchParams(new FormData(form));
  const response = await fetch(loginTargetUrl(), {
    method: 'POST',
    body,
    credentials: 'same-origin',
    headers: {
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
  });

  if (response.status === 204) {
    message.textContent = 'Login successful. Redirecting...';
    message.dataset.state = 'ok';
    window.location.href = successRedirectUrl();
    return;
  }

  if (response.status === 401) {
    message.textContent = 'Login failed.';
    return;
  }

  message.textContent = 'Unexpected server response.';
});
