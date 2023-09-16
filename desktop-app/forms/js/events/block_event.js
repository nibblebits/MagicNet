
window.api.receive("initialize-data", (event_data) => {
  let block_data = event_data.data.new_block_event.block;
  console.log('block data;' + block_data);
  $('.block-hash').html(block_data.hash);
  $('.block-prev-hash').html(block_data.prev_hash);
  $('.block-public-key').html(block_data.key);

  const unixTimestamp = block_data.time;
  const dateObject = new Date(unixTimestamp * 1000); // convert to milliseconds by multiplying with 1000
  const humanReadableDate = dateObject.toLocaleString(); // convert to a human-readable date-time string
  $('.block-timestamp').html(humanReadableDate);
  
});

window.addEventListener("DOMContentLoaded", () => {

});
