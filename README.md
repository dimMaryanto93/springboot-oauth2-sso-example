# Spring Security - Oauth2 SSO example

Belajar Web Security dengan fitur single sign on (SSO)

- Fitur Grant type Authorization code
    
    - request code : [klick disini](http://localhost:8080/oauth/authorize?grant_type=authorization_code&client_id=client-code&client_secret=123456&redirectUrl=http://localhost:8080/&response_type=code)
    
        ```bash
        http://localhost:8080/oauth/authorize?grant_type=authorization_code&client_id=client-code&client_secret=123456&redirectUrl=http://localhost:8080/&response_type=code
        ```
    
    - request token : 
    
        ```bash 
        curl -X POST \
          http://localhost:8080/oauth/token \
          -H 'Authorization: Basic Y2xpZW50LWNvZGU6MTIzNDU2' \
          -H 'Cache-Control: no-cache' \
          -H 'Content-Type: application/x-www-form-urlencoded' \
          -d 'grant_type=authorization_code&code=1HQ2Gh'
        ```

- Fitur Grant type Password

    ```bash
    curl -X POST \
      'http://localhost:8080/oauth/token?grant_type=password&client_id=client-code&username=user&password=password' \
      -H 'Authorization: Basic Y2xpZW50LWNvZGU6MTIzNDU2' \
      -H 'Postman-Token: f2b78553-073a-46c7-8a3e-dca6ccdc1fef'
    ```