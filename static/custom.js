$('#messagemodal').on('show.bs.modal', function (event) {
  var button = $(event.relatedTarget) // Button that triggered the modal
  var recipient = button.data('username') // Extract info from data-* attributes
  // If necessary, you could initiate an AJAX request here (and then do the updating in a callback).
  // Update the modal's content. We'll use jQuery here, but you could use a data binding library or other methods instead.
  var modal = $(this)
  modal.find('.modal-title').text('New message to ' + recipient)
  $('input[name=recipient]').val(recipient)
})

function searchBroadcasts() {

  var input1, input2, filter_msg, filter_upi, p, i, txtValue,txtValue2,  containers, s;
  input1 = document.getElementById('search_msg');
  input2 = document.getElementById('search_user');
  filter_upi = input2.value.toUpperCase();
  filter_msg = input1.value.toUpperCase();
  containers = document.getElementsByClassName("broadcast_container")

  // Loop through all list items, and hide those who don't match the search query
  for (i = 0; i < containers.length; i++) {
    p = containers[i].getElementsByTagName("p")[0];
    txtValue = p.textContent || p.innerText;

    s = containers[i].getElementsByTagName("span")[0];
    txtValue2 = s.textContent || s.innerText;
    txtValue2 = txtValue2.split(":")[0];

    if ((txtValue.toUpperCase().indexOf(filter_msg) > -1) && (txtValue2.toUpperCase().indexOf(filter_upi) > -1)) {
      containers[i].style.display = "";
    } else {
      containers[i].style.display = "none";
    }
  }
}


