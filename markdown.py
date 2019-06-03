import cgi
import html
import parser
import re


def markdown(text):
    #Remove any HTML markup at the start so that we can add our own later
    text = cgi.escape(text)
    bold = re.findall('(\*\*)(.*?)\\1', text)

    #Bold Text
    for i in bold:
        oldstring = i[0] + i[1] + i[0]
        text = text.replace(oldstring, "<strong>" + i[1] + "</strong>")


    header = re.findall('(#+)(.*)', text)

    #Headers
    for head in header:
        headernum = len(head[0])
        headerText = head[1]
        oldstring = head[0] + head[1]
        newstring = "<h" + str(headernum) + ">" + headerText + "</h" + str(headernum) + ">"
        text = text.replace(oldstring, newstring)
    #Emphasis
    emphasis_matches = re.findall('(\*)(.*?)\\1', text)
    for match in emphasis_matches:
        string = match[1]
        oldstring = match[0] + string + match[0]
        newstring = "<em>" + string + "</em>"
        text = text.replace(oldstring, newstring)

    #Code
    code_matches = re.findall('`(.*?)`', text)
    for code in code_matches:
        oldstring = "`" + code + "`"
        newstring = "<code>" + code + "</code>"
        text = text.replace(oldstring, newstring)
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