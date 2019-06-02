import cgi
import html
import parser
import re


def markdown(text):
    #Remove any HTML markup at the start so that we can add our own later
    text = cgi.escape(text)
    bold = re.findall('\*.*?\*', text)
    #Bold Text
    for i in bold:
        string = i.split("*")[1]
        text = text.replace(i, "<strong>" + string + "</strong>")
    #Image links
    img = re.findall("(?:!\[(.*?)\]\((.*?)\))", text)
    for i in img:
        description = i[0]
        url = i[1]
        oldstring = "![" + description + "](" + url + ")"
        newstring = "<img src=\"" + url + "\" alt=\"" + description + "\">"
        text = text.replace(oldstring, newstring)
    #Regular Inline Links
    links = re.findall("(?:\[(.*?)\]\((.*?)\))", text)
    for link in links:
        description = link[0]
        url = link[1]  
        oldstring = "[" + description + "](" + url + ")"
        newstring = "<a href=\"" + url + "\">" + description + "</a>"
        text = text.replace(oldstring, newstring) 
    return text