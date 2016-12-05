This is the project for handling user and server side certificated based authentication for ssh.

There are two 'projects'
  client 
    server       -> generates certifcates based on LDAP keys. For v1 it should auth
                    user using ldap usernames/passwords. For v2 should be able to use
                    openidconnect endpoints.
    prodaccess   -> connects to the server and puts keys in the right location
                    for user to use. Should be a single binary with no dependencies
                    (so that is easy to generate for multiple platforms)
  
  host(for future)
    server       -> generates host certificates.. authentication.. still unknown.
    requestor    -> able to connect to server to request cert...

