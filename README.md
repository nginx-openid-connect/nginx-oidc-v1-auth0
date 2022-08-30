# nginx-oidc-v1-auth0

[Reference implementation v1](https://github.com/nginx-openid-connect/nginx-oidc-core-v1) enhancement of NGINX Plus as relying party for OpenID Connect authentication w/ Auth0.

This repo provides the information of how to set up Auth0, integrate with NGINX Plus, and test using a containerized NGINX Plus app, a frontend OIDC simulation tool, and a NGINX Dev Portal.

## 1. Enhanced Features

The following features are enhanced from the [nginx-oidc-core-v1](https://github.com/nginx-openid-connect/nginx-oidc-core-v1):

- Access token
- Login endpoint
- Userinfo endpoint
- Logout endpoint: standard, custom params
- Frontend simulation tool: login, logout, proxied API w/ access-token

## 2. Getting Started

> | Steps               | Docs                                                                 |
> | ------------------- | -------------------------------------------------------------------- |
> | 1) IdP Setup        | [How To Configure Auth0](./docs/01-Auth0-Setup.md)                   |
> | 2) NGINX Plus Setup | [How To Configure NGINX Plus](./docs/02-NGINX-Plus-Setup.md)         |
> | 3) OIDC Test        | [How To Test OIDC in Containerized App](./docs/03-Container-Test.md) |
> |                     | [How To Test OIDC in Dev Portal](./docs/04-NGINX-DevPortal-Test.md)  |

## References

- [NGINX OIDC Core v1.0: Forked from NGINX GitHub](https://github.com/nginx-openid-connect/nginx-oidc-core-v1)
- [NGINX Plus: Single Sign-On With Auth0](https://docs.nginx.com/nginx/deployment-guides/single-sign-on/auth0/)
