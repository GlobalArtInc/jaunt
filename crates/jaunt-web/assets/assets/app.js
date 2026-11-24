const status = document.getElementById("status");

fetch("/v1/web/session", { credentials: "same-origin" })
  .then((response) => (response.ok ? response.json() : null))
  .then((session) => {
    if (session) {
      status.textContent = "Signed in as " + session.email;
    }
  })
  .catch(() => {
    status.textContent = "The server could not be reached.";
  });
