// Inside Renderer Process

window.addEventListener("DOMContentLoaded", () => {

  function appendCardBodyForEvent(event, cardBody) {
    const cardText = document.createElement("p");
    cardText.classList.add("card-text");
    cardText.textContent = `Event Type: ${event.type}`;
    cardBody.appendChild(cardText);
  }

  function makeCardForEvent(event) {
    const card = document.createElement("div");
    card.classList.add("card");

    const cardBody = document.createElement("div");
    cardBody.classList.add("card-body");

    appendCardBodyForEvent(event, cardBody);
    card.appendChild(cardBody);

    return card;
  }

  window.api.receive("magicnet-event-received", (event_data) => {
    const card = makeCardForEvent(event_data);
    const magicNetEvents = document.querySelector(".magicnet-events");
    
    if (magicNetEvents) {
      magicNetEvents.appendChild(card);
    }
  });

  window.api.receive("set-connection-status-label", (message) => {
    console.log(`received msg: ${message}`);
    document.querySelector(".server-connected-status-label").textContent = message;
  });

});
