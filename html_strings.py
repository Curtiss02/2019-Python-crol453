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
