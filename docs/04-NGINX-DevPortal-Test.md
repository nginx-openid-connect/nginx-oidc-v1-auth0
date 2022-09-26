# How To Set Up NGINX Dev Portal OIDC for Auth0 Integration

Take the following steps to set up NGINX Dev Portal OIDC and test it for Auth0 integration.

## 1. Prerequisites

- [**Set up Auth0**](./01-Auth0-Setup.md)

  Ensure that you use **different application and callback/logout URLs** as the following example unlike that are already created to test your [containerized NGINX Plus](./02-NGINX-Plus-Setup.md).

  | Category              | Example                                      |
  | --------------------- | -------------------------------------------- |
  | Application Name      | `nginx-devportal-app`                        |
  | Allowed Callback URLs | `http://nginx.devportal.auth0.test/_codexch` |
  | Allowed Logout URLs   | `http://nginx.devportal.auth0.test/_logout`  |

- Edit `hosts` file in your laptop via if you want to locally test your app:

  ```bash
  $ sudo vi /etc/hosts
  127.0.0.1 nginx.devportal.auth0.test  #Note : The provided IP address should be of the host where you installed the Dev Portal packages . 
  # Also make sure your controller and Dev Portal /etc/hosts files have similar entries.
  ```

## 2. Install NGINX API Connectivity Manager

- [Download NGINX Management Suite](https://docs.nginx.com/nginx-management-suite/)

- [Install NGINX API Connectivity Manager](https://docs.nginx.com/nginx-management-suite/admin-guides/installation/install-guide/)

## 2. Set Up NGINX Dev Portal

Configure a Dev Portal by either referencing **NGINX Management Suite Docs** of [How To Set Up a NGINX Dev Portal](https://docs.nginx.com/nginx-management-suite/acm/getting-started/add-devportal/) or taking the following steps of calling APIs:

> **Note**:
>
> [Download an example of postman collection](./ACM-DevPortal-OIDC.postman_collection.json) for easily testing the following steps.

- Open a Postman collection, and edit ACM password and variables:
  ![](./img/postman-auth.png)
  ![](./img/postman-variables.png)

- Create a `infra > workspace`:

  > `POST https://{{ctrl_ip}}/api/acm/v1/infrastructure/workspaces`
  >
  > `Body`:
  >
  > ```json
  > {
  >   "name": "{{infraworkspacename}}"
  > }
  > ```

- Create a `proxy > workspace`:

  > `POST https://{{ctrl_ip}}/api/acm/v1/services/workspaces`
  >
  > `Body`:
  >
  > ```json
  > {
  >   "name": "{{proxyworkspacename}}"
  > }
  > ```

- Create an environment of `Dev Portal`:

  > `POST https://{{ctrl_ip}}/api/acm/v1/infrastructure/workspaces/{{infraworkspacename}}/environments`
  >
  > `Body`:
  >
  > ```json
  > {
  >   "name": "{{environmentname}}",
  >   "functions": ["DEVPORTAL"],
  >   "proxies": [
  >     {
  >       "proxyClusterName": "{{devPinstanceGroupName}}",
  >       "hostnames": ["{{devPenvironmentHostname}}"],
  >       "runtime": "PORTAL-PROXY",
  >       "policies": {
  >         "oidc-authz": [
  >           {
  >             "action": {
  >               "jwksURI": "https://{{auth0Domain}}/.well-known/jwks.json",
  >               "tokenEndpoint": "https://{{auth0Domain}}/oauth/token",
  >               "userInfoEndpoint": "https://{{auth0Domain}}/userinfo",
  >               "authorizationEndpoint": "https://{{auth0Domain}}/authorize",
  >               "logOffEndpoint": "https://{{auth0Domain}}/v2/logout",
  >               "logOutParams": [
  >                 {
  >                   "paramType": "QUERY",
  >                   "key": "returnTo",
  >                   "value": "http://{{devPenvironmentHostname}}/_logout"
  >                 },
  >                 {
  >                   "key": "client_id",
  >                   "paramType": "QUERY",
  >                   "value": "{{clientId}}"
  >                 }
  >               ],
  >               "TokenParams": [
  >                 {
  >                   "paramType": "HEADER",
  >                   "key": "Accept-Encoding",
  >                   "value": "gzip"
  >                 }
  >               ]
  >             },
  >             "data": [
  >               {
  >                 "clientID": "{{clientId}}",
  >                 "clientSecret": "{{clientSecret}}",
  >                 "scopes": "openid+profile+email+offline_access"
  >               }
  >             ]
  >           }
  >         ]
  >       }
  >     }
  >   ]
  > }
  > ```

- Get an environment of `Dev Portal`:

  > `GET https://{{ctrl_ip}}/api/acm/v1/infrastructure/workspaces/{{infraworkspacename}}/environments`
  >
  > `Response`:
  >
  > ```
  > {
  >     :
  >     curl -k https://<CTRL-FQDN>/install/nginx-agent > install.sh && sudo sh install.sh -g devp-group && sudo systemctl start nginx-agent
  >     :
  > }
  > ```

- SSH into the instance of Dev Portal, and run the following commands:

  ```ssh
  curl -k https://<CTRL-FQDN>/install/nginx-agent > install.sh && sudo sh install.sh -g devp-group && sudo systemctl start nginx-agent
  ```

- Option 1. Upsert an environment of `Dev Portal` for `none-PKCE`

  > `PUT https://{{ctrl_ip}}/api/acm/v1/infrastructure/workspaces/{{infraworkspacename}}/environments/{{environmentname}}`
  >
  > `Body`:
  >
  > ```json
  > {
  >   "name": "{{environmentname}}",
  >   "type": "NON-PROD",
  >   "functions": ["DEVPORTAL"],
  >   "proxies": [
  >     {
  >       "proxyClusterName": "{{devPinstanceGroupName}}",
  >       "hostnames": ["{{devPenvironmentHostname}}"],
  >       "runtime": "PORTAL-PROXY",
  >       "listeners": [
  >         {
  >           "ipv6": false,
  >           "isTLSEnabled": false,
  >           "port": 80,
  >           "transportProtocol": "HTTP"
  >         }
  >       ],
  >       "policies": {
  >         "oidc-authz": [
  >           {
  >             "action": {
  >               "authFlowType": "AUTHCODE",
  >               "authorizationEndpoint": "https://{{auth0Domain}}/authorize",
  >               "jwksURI": "https://{{auth0Domain}}/.well-known/jwks.json",
  >               "logOffEndpoint": "https://{{auth0Domain}}/v2/logout",
  >               "logOutParams": [
  >                 {
  >                   "key": "returnTo",
  >                   "paramType": "QUERY",
  >                   "value": "http://{{devPenvironmentHostname}}/_logout"
  >                 },
  >                 {
  >                   "key": "client_id",
  >                   "paramType": "QUERY",
  >                   "value": "{{clientId}}"
  >                 }
  >               ],
  >               "tokenEndpoint": "https://{{auth0Domain}}/oauth/token",
  >               "tokenParams": [
  >                 {
  >                   "key": "Accept-Encoding",
  >                   "paramType": "HEADER",
  >                   "value": "gzip"
  >                 }
  >               ],
  >               "uris": {
  >                 "loginURI": "/login",
  >                 "logoutURI": "/logout",
  >                 "redirectURI": "/_codexch",
  >                 "userInfoURI": "/userinfo"
  >               },
  >               "userInfoEndpoint": "https://{{auth0Domain}}/userinfo"
  >             },
  >             "data": [
  >               {
  >                 "appName": "nginx-devportal-app",
  >                 "clientID": "{{clientId}}",
  >                 "clientSecret": "{{clientSecret}}",
  >                 "scopes": "openid+profile+email+offline_access",
  >                 "source": "ACM"
  >               }
  >             ]
  >           }
  >         ]
  >       }
  >     }
  >   ]
  > }
  > ```

- Option 2. Upsert an environment of `Dev Portal` for `PKCE`:

  > `PUT https://{{ctrl_ip}}/api/acm/v1/infrastructure/workspaces/{{infraworkspacename}}/environments/{{environmentname}}`
  >
  > `Body`:
  >
  > ```
  > {
  >        :
  >   "authFlowType": "PKCE",
  >        :
  >   "clientSecret": "",
  >        :
  > }
  > ```

## 3. Test Dev Portal OIDC with Auth0

- Open a web browser and access the Dev Portal's FQDN like `http://nginx.devportal.auth0.test`.
- ![](./img/logged-out-devPortal.png)
- Try `Login` and `Logout`.
- ![](./img/login-auth0-devPortal.png)
- ![](./img/logged-in-devPortal.png)
- Test the above TWO steps after changing IdP (PKCE option) and updating Dev Portal via NGINX ACM API.
