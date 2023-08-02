window.addEventListener('DOMContentLoaded', () => {

  const timerElement = document.getElementById('myTimer');

  window.api.receive("myCounterUpdated", (seconds) => {
    let hours = Math.floor(seconds / 3600).toString().padStart(2, '0');
    let minutes = Math.floor((seconds % 3600) / 60).toString().padStart(2, '0');
    let real_seconds = Math.floor(seconds % 60).toString().padStart(2, '0');
    timerElement.textContent = `${hours}:${minutes}:${real_seconds}`;
  });
  
  const toggleBtn = document.getElementById("toggleBtn");

  toggleBtn.addEventListener("click", (event) => {
      var toggle = 'on';
      const button = event.target;

      if (button.classList.contains('btn-start')) {
          toggle = 'on';
          button.classList.remove('btn-start');
          button.classList.remove('btn-success');
          button.classList.add('btn-stop');
          button.classList.add('btn-danger');
          button.textContent = 'Stop';
      } else {
          toggle = 'off';
          button.classList.remove('btn-stop');
          button.classList.remove('btn-danger');
          button.classList.add('btn-start');
          button.classList.add('btn-success');
          button.textContent = 'Start';
      }
      window.api.send("toggle-stopwatch", toggle);
  });
});

const resetBtn = document.getElementById('resetButton');
resetBtn.addEventListener('click', (event) => {
  window.api.send("reset-stopwatch");
});
