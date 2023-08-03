// Inside Renderer Process

window.addEventListener("DOMContentLoaded", () => {

  window.api.receive("magicnet-event-received", (event_data) => {
    // Create a new bootstrap card
    const card = document.createElement('div');
    card.classList.add('card');

    // Create card body
    const cardBody = document.createElement('div');
    cardBody.classList.add('card-body');

    // Create card text
    const cardText = document.createElement('p');
    cardText.classList.add('card-text');
    cardText.textContent = 'Event Type: ' + event_data.type;

    // Append card text to card body
    cardBody.appendChild(cardText);

    // Append card body to card
    card.appendChild(cardBody);

    // Find the "magicnet-events" element and append the new card to it
    const magicNetEvents = document.querySelector('.magicnet-events');
    if (magicNetEvents) {
      magicNetEvents.appendChild(card);
    }
  });

  window.api.receive("set-connection-status-label", (message) => {
    console.log("received msg: " + message);
    $(".server-connected-status-label").text(message);
  });
});
