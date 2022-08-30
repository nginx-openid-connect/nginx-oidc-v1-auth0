# How To Set Up NGINX Plus OIDC for Auth0 Integration

Take the following steps to set up NGINX Plus as the OpenID Connect relying party that runs.

## Configure NGINX OpenID Connect

1. Clone the [nginx-openid-connect/nginx-oidc-v1-auth0](git@github.com:nginx-openid-connect/nginx-oidc-v1-auth0.git) GitHub repository, or download the repo files.

   ```bash
   git clone https://github.com/nginx-openid-connect/nginx-oidc-v1-auth0.git
   ```

2. In the `oidc_frontend_backend.conf` file, update the upstreams of `my_frontend_site` and `my_backend_app` with the address of the application that you want to add OIDC authorization to.

   ```nginx
   # Sample upstream server for the frontend site.
   #
   upstream my_frontend_site {
       zone my_frontend_site 64k;
       server 127.0.0.1:9091;
   }

   # Sample upstream server for the backend app.
   #
   upstream my_backend_app {
       zone my_backend_app 64k;
       server 127.0.0.1:9092;
   }
   ```

3. In the `openid_connect_configuration.conf`, update IdP well known points.

   You could find the IDP domain in the **Basic Information** section.  
   ![](./img/basic-domain.png)

   ```nginx
   map $host $idp_domain {
       default '{{Your-IDP-Domain}}';
   }

   map $host $oidc_authz_endpoint {
       default https://$idp_domain/authorize;
   }

   map $host $oidc_token_endpoint {
       default https://$idp_domain/oauth/token;
   }

   map $host $oidc_jwt_keyfile {
       default https://$idp_domain/.well-known/jwks.json;
   }

   map $host $oidc_logout_endpoint {
       default https://$idp_domain/v2/logout;
   }

   map $host $oidc_userinfo_endpoint {
       default https://$idp_domain/userinfo;
   }

   map $host $oidc_client {
       default "{{Your-IDP-Client-ID}}";
   }

   map $host $oidc_logout_query_params_enable {
       default 1; # 0: OIDC RP-initiated logout, 1: custom logout
   }

   map $host $oidc_logout_query_params {
       default '{
           "client_id": "$oidc_client",
           "returnTo" : "$redirect_base/_logout"
       }';
   }
   ```

4. In the `openid_connect_configuration.conf`, update `$oidc_client_secret`, and `oidc_pkce_enable`.

   - Option 1. Update the following configuration if you don't enable **PKCE**.

     ```nginx
     map $host $oidc_client_secret {
         default "{{Your-IDP-Client-Secret}}";
     }

     map $host $oidc_pkce_enable {
         default 0;
     }
     ```

   - Option 2. Update the following configuration if you enable **PKCE**.

     ```nginx
     map $host $oidc_client_secret {
         default ""; # Remove the client secret
     }

     map $host $oidc_pkce_enable {
         default 1;
     }
     ```

## Optional Configuration

This repo provides a sample container environment. So you can skip this step if you would like to simpley test with a container.

1. Copy the following files to the `/etc/nginx/conf.d` directory on the host machine where NGINX Plus is installed:

   - `oidc_frontend_backend.conf`
   - `openid_connect.js`
   - `openid_connect.server_conf`
   - `openid_connect_configuration.conf`
   - `docker/build-context/nginx/test/proxy_server_test.conf`

2. Update `/etc/nginx/nginx.conf` with the following information:

   ```nginx
   http {
       :
       include conf.d/openid_connect_configuration.conf;
       include conf.d/oidc_frontend_backend.conf;
       include conf.d/frontend.conf;
       include test/proxy_server_test.conf;
       :
   }
   ```

3. Copy the following directory to the `/usr/share/nginx/html/` directory on the host machine where NGINX Plus is installed:

   ```bash
    cp -R docker/build-context/content/ /usr/share/nginx/html/
   ```

   > Note:
   >
   > Skip this step if you have your frontend files as these files are a sample frontend app to test the OIDC.

4. Reload the NGINX configuration:

   ```bash
   sudo nginx -s reload
   ```
