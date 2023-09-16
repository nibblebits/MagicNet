
window.api.receive("initialize-data", (event_data) => {
    console.log(event_data.data);
    let event_type_id = window.MagicNetEventTypeInformation[event_data.type].id;
    let event_type_title = window.MagicNetEventTypeInformation[event_data.type].title;
    let event_type_description = window.MagicNetEventTypeInformation[event_data.type].description;
  
    $('.event-type').html(event_type_title);
    $('.event-id').html(event_type_id);
    $('.event-description').html(event_type_description);
  
    // Setup the block views..
  
    $(document).prop('title', event_type_title +  ' #' + event_data.id);
  });
  