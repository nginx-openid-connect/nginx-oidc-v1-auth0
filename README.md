# nginx-oidc-auth0-v1

Reference implementation v1 enhancement of NGINX Plus as relying party for OpenID Connect authentication w/ Auth0.

## Enhanced Features

The following features are enhanced from the [nginx-oidc-core-v1](https://github.com/nginx-openid-connect/nginx-oidc-core-v1):

- Access token
- Login endpoint
- Userinfo endpoint
- Custom logout parameter
- Frontend simulation tool

## Getting Started

- **Prerequisites**

  - [Install Docker](https://docs.docker.com/engine/install/)
  - [Configure Auth0](https://docs.nginx.com/nginx/deployment-guides/single-sign-on/auth0/)
  - Edit your hots file via `$ sudo vi /etc/hosts`:
    ```bash
    127.0.0.1 nginx-plus-app
    ```
  - [Download and copy NGINX Plus license files](https://www.nginx.com/free-trial-request/) to `./docker/build-context/ssl`
    ```
    nginx-repo.crt
    nginx-repo.key
    ```

- **Start** Docker containers

  ```bash
  $ make start
  ```

- **Watch** Docker containers status

  ```bash
  $ make ps
  ```

  ![](./img/docker-ps-nginx-oidc-auth0.png)

- **Stop** Docker containers

  ```bash
  $ make down
  ```

- **Remove** Docker container images

  ```bash
  $ make clean
  ```
