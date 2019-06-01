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
            <a class="nav-link" href="#">Private Messages</a>
        </li>
        </ul>
        <span class="navbar-text">""" + username + """</span>
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
login_form = """<form action="/signin" method="post" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="inputUsername">Username</label>
                    <input type="text" name="username" class="form-control" id="inputUsername" aria-describedby="usernameHelp" placeholder="Enter username">
                    <small id="usernameHelp" class="form-text text-muted">Username is your UPI.</small>
                </div>
                <div class="form-group">
                    <label for="inputPassword">Password</label>
                    <input type="password" name="password" class="form-control" id="inputPassword" placeholder="Password">
                </div>
                <div class="form-check">
                    <input type="checkbox" name="hidden" class="form-check-input" id="hiddenmode">
                    <label class="form-check-label" for="hiddenmode">Hidden from Online User List (No Report)</label>
                </div>
                <button type="submit" class="btn btn-primary">Submit</button>
                </form>
                </div></div>"""
