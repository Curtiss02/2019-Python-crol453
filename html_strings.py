import cgi

def getNavbar(username):

    nav = """<nav class="navbar navbar-expand-lg navbar-light bg-light">
    <a class="navbar-brand" href="#">Chatter</a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarText" aria-controls="navbarText" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarText">
        <ul class="navbar-nav mr-auto">
        <li class="nav-item active">
            <a class="nav-link" href="/">Home <span class="sr-only">(current)</span></a>
        </li>
        <li class="nav-item">
            <a class="nav-link" href="/users">User Lists</a>
        </li>
        <li class="nav-item">
            <a class="nav-link" href="/private">Private Messages</a>
        </li>
        </ul>
        <a href="/account"><span class="navbar-text">""" + username + """</span></a>
        <span class="navbar-text"></span>
        <a class="btn btn-primary" href="/signout" role="button">Sign Out</a>
    </div>
    </nav>"""

    return nav

jumbotron = """<div class="jumbotron text-center" style="background-color: #e3f2fd;">
                    <h1>Welcome to Chatter!</h1>
                    </div>
            """
jumbotron_login = """<div class="jumbotron text-center" style="background-color: #e3f2fd;">
                    <h1>Welcome to Chatter!</h1>
                    <p>Login to join the social media sensation!</p> 
                    </div>"""
login_form = """<div class="row"><div class="col-sm-9 col-md-7 col-lg-5 mx-auto">
                    <form action="/signin" method="post" enctype="multipart/form-data">
                <div class="form-group ">
                    <label for="inputUsername">Username</label>
                    <input type="text" name="username" class="form-control" id="inputUsername" aria-describedby="usernameHelp" placeholder="Enter username">
                    <small id="usernameHelp" class="form-text text-muted">Username is your UPI.</small>
                </div>
                <div class="form-group">
                    <label for="inputPassword">Password</label>
                    <input type="password" name="password" class="form-control" id="inputPassword" placeholder="Password">
                </div>
                <button type="submit" class="btn btn-primary">Submit</button>
                </form>
                </div></div></div></div>"""
pills = """<div class=\"container\"><div class=\"row\">
<div class="nav flex-column nav-pills" id="v-pills-tab" role="tablist" aria-orientation="vertical">
  <a class="nav-link active" id="v-pills-home-tab" data-toggle="pill" href="#v-pills-home" role="tab" aria-controls="v-pills-home" aria-selected="true">User1</a>
  <a class="nav-link" id="v-pills-profile-tab" data-toggle="pill" href="#v-pills-profile" role="tab" aria-controls="v-pills-profile" aria-selected="false">User2</a>
  <a class="nav-link" id="v-pills-messages-tab" data-toggle="pill" href="#v-pills-messages" role="tab" aria-controls="v-pills-messages" aria-selected="false">user3</a>
  <a class="nav-link" id="v-pills-settings-tab" data-toggle="pill" href="#v-pills-settings" role="tab" aria-controls="v-pills-settings" aria-selected="false">User4</a>
</div>
<div class="tab-content" id="v-pills-tabContent">
  <div class="tab-pane fade show active" id="v-pills-home" role="tabpanel" aria-labelledby="v-pills-home-tab">a</div>
  <div class="tab-pane fade" id="v-pills-profile" role="tabpanel" aria-labelledby="v-pills-profile-tab">b</div>
  <div class="tab-pane fade" id="v-pills-messages" role="tabpanel" aria-labelledby="v-pills-messages-tab">c</div>
  <div class="tab-pane fade" id="v-pills-settings" role="tabpanel" aria-labelledby="v-pills-settings-tab">d</div>
</div>
</div>
</div>"""

userlist_head = """<table class="table">
    <thead class="thead-dark">
    <tr>
    <th scope="col">Username</th>
    <th scope="col">Send Message</th>
    <th scope="col">Connection Address</th>
    <th scope="col">Connection Location</th>
    <th scope="col">Public Key</th>
    <th scope="col">Last Seen</th>
    <th scope="col">Status</th>
    <th scope="col">Reachable</th>
    </tr>
    </thead>
    <tbody>"""

messagemodal = """<div class="modal fade" id="messagemodal" tabindex="-1" role="dialog" aria-labelledby="messagemodalLabel" aria-hidden="true">
  <div class="modal-dialog" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="messagemodalLabel">New message</h5>
        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
          <span aria-hidden="true">&times;</span>
        </button>
      </div>
      <div class="modal-body">
        <form action="/send_private" method="post" enctype="multipart/form-data">
          <div class="form-group">
            <label for="recipient-name" class="col-form-label">Username:</label>
            <input type="text" name="recipient" class="form-control" id="recipient-name">
          </div>
          <div class="form-group">
            <label for="message-text" class="col-form-label">Message:</label>
            <textarea class="form-control" name="message" id="message-text"></textarea>
            <input type="hidden" id="prevurl" name="previous" value="users">
          </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
        <button type="submit" class="btn btn-primary">Send message</button>
      </div>
    </form>

    </div>
  </div>
</div>
"""