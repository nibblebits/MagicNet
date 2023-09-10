
window.api.receive("initialize-data", (event_data) => {
  let event_type_title = window.MagicNetEventTypeInformation[event_data.type].title;
  $('.event-name').html(event_type_title);
  $(document).prop('title', event_type_title +  ' #' + event_data.id);
});

window.addEventListener("DOMContentLoaded", () => {

});
