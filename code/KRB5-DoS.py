import kerberos
# import random

while True:
    try:
        # unknown users (principles) cause more CPU!
        """
        print kerberos.checkPassword("user", \
                "badpassword@123", \
                "krbtgt/client.example.com", \
                "EXAMPLE.COM")
        """

        # known users (principles) cause more CPU!
        print kerberos.checkPassword("user1", \
                "badpassword@123", \
                "krbtgt/client.example.com", \
                "EXAMPLE.COM")

    except Exception, exc:
        # print exc
        pass
