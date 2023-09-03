const eventsCardBuilder = {
  appendCardHeader(event, cardHeader) {
    const dflexDiv = $("<div></div>").addClass(
      "d-flex justify-content-between"
    );
    const dflexSpan = $("<span></span>").html("Notification");
    const dflexSmallTime = $("<small></small>")
      .addClass("text-muted")
      .html("5 mins ago");

    dflexDiv.append(dflexSpan, dflexSmallTime);
    $(cardHeader).append(dflexDiv);
  },
  appendCardBodyForEvent(event, cardBody) {
    const cardTitle = $("<h5></h5>")
      .addClass("card-title")
      .html(window.MagicNetEventTypeInformation[event.type].title);

    const cardText = $("<p></p>")
      .addClass("card-text")
      .html(window.MagicNetEventTypeInformation[event.type].description);

    $(cardBody).append(cardTitle, cardText);
  },
  appendCardFooterForEvent(event, cardFooter) {
    const viewDetailsBtn = $("<a></a>")
      .addClass("btn btn-primary events-view-details-btn")
      .attr("data-event", JSON.stringify(event))
      .html("View Details");

    $(cardFooter).append(viewDetailsBtn);
  },

  makeCardForEvent(event) {
    const card = $("<div></div>").addClass("card mt-3");
    const cardHeader = $("<div></div>").addClass("card-header");
    this.appendCardHeader(event, cardHeader[0]);  // Passing the DOM element
    
    const cardBody = $("<div></div>").addClass("card-body");
    this.appendCardBodyForEvent(event, cardBody[0]);  // Passing the DOM element
    
    const cardFooter = $("<div></div>").addClass("card-footer");
    this.appendCardFooterForEvent(event, cardFooter[0]);  // Passing the DOM element
    
    card.append(cardHeader, cardBody, cardFooter);
    
    card.on("click", ".events-view-details-btn", function() {
        let viewDetailsBtn = $(this);
        // Extract the event
        let event = JSON.parse(viewDetailsBtn.attr("data-event"));
        window.api.send('eventShowDialog', event);
    });
    
    return card[0];  // Returning the DOM element
},

};

export default eventsCardBuilder;
