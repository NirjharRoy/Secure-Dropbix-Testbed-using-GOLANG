# Secure-Dropbox-Testbed-using-GOLANG
use Go to build the functions needed to implement "encrypted dropbox", a cryptographically authenticated and secure file store (Actually, a Key-Value store; we have abstracted concept of files into key-value pairs so that you don’t have to deal with raw files directly)

This project and the supporting material provided is based on material
created by Nick Weaver and Cameron Rasmussen of the University of California, Berke-
ley.

# Overview and motivation for this project
Storing files on a server and sharing them with friends and collaborators is very useful.
Commercial services like Dropbox or Google Drive are popular examples of a file store
service (with convenient filesystem interfaces). But what if you couldn’t trust the server
you wanted to store your files on? What if you wanted to securely share and collaborate
on files, even if the owner of the server is malicious? Especially since both Dropbox
and Google Drive don’t actually encrypt the user data.
