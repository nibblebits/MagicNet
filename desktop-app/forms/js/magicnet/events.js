
const eventsCardBuilder = {
  appendCardHeader(event, cardHeader) {
    const dflexDiv = document.createElement("div");
    dflexDiv.classList.add("d-flex");
    dflexDiv.classList.add("justify-content-between");
    var dflexSpan = document.createElement("span");
    dflexSpan.innerHTML = "Notification";
    var dflexSmallTime = document.createElement("small");
    dflexSmallTime.classList.add("text-muted");
    dflexSmallTime.innerHTML = "5 mins ago";

    dflexDiv.appendChild(dflexSpan);
    dflexDiv.appendChild(dflexSmallTime);
    cardHeader.appendChild(dflexDiv);
  },
  appendCardBodyForEvent(event, cardBody) {
    const cardTitle = document.createElement("h5");
    cardTitle.innerHTML = window.MagicNetEventTypeInformation[event.type].title;
    
    cardTitle.classList.add("card-title");
    const cardText = document.createElement("p");
    cardText.classList.add("card-text");
    cardText.innerHTML = window.MagicNetEventTypeInformation[event.type].description;
    cardBody.appendChild(cardTitle);
    cardBody.appendChild(cardText);
  },

  appendCardFooterForEvent(event, cardFooter) {
    const viewDetailsBtn = document.createElement("a");
    viewDetailsBtn.classList.add("btn");
    viewDetailsBtn.classList.add("btn-primary");
    viewDetailsBtn.classList.add("events-view-details-btn");
    viewDetailsBtn.setAttribute("data-event-id", event.ptr_id);
    viewDetailsBtn.innerHTML = "View Details";
    cardFooter.appendChild(viewDetailsBtn);
  },

  makeCardForEvent(event) {
    const card = document.createElement("div");
    card.classList.add("card");
    card.classList.add("mt-3");

    const cardHeader = document.createElement("div");
    cardHeader.classList.add("card-header");
    this.appendCardHeader(event, cardHeader);

    const cardBody = document.createElement("div");
    cardBody.classList.add("card-body");

    this.appendCardBodyForEvent(event, cardBody);

    const cardFooter = document.createElement("div");
    cardFooter.classList.add("card-footer");
    this.appendCardFooterForEvent(event, cardFooter);
    card.appendChild(cardHeader);
    card.appendChild(cardBody);
    card.appendChild(cardFooter);

    return card;
  },
};

export default eventsCardBuilder;
