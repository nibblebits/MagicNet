// Inside Renderer Process

import eventsCardBuilder from "./magicnet/events.js"

window.addEventListener("DOMContentLoaded", () => {

//   <div class="card">
//   <div class="card-header">
//     <div class="d-flex justify-content-between">
//       <span>Notification</span>
//       <small class="text-muted">5 mins ago</small>
//     </div>
//   </div>
//   <div class="card-body">
//     <h5 class="card-title">New Block Created</h5>
//     <p class="card-text">A new block has been added to the blockchain. This block contains 500 transactions and was mined by Node #42.</p>
//   </div>
//   <div class="card-footer">
//     <a href="#" class="btn btn-primary">View Details</a>
//   </div>
// </div>

  

  window.api.receive("magicnet-event-received", (event_data) => {
    const card = eventsCardBuilder.makeCardForEvent(event_data);
    console.log(card);
    const magicNetEvents = $(".magicnet-events");
    
    if (magicNetEvents) {
      magicNetEvents.append(card);
    }
  });

  window.api.receive("set-connection-status-label", (message) => {
    console.log(`received msg: ${message}`);
    document.querySelector(".server-connected-status-label").textContent = message;
  });

});
