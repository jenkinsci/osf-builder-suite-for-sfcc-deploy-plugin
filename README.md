# OSF Builder Suite For Salesforce Commerce Cloud :: Deploy
Deploy your build to a Salesforce Commerce Cloud instance

**OSF Builder Suite For Salesforce Commerce Cloud :: Deploy** is an alternative to **Salesforce Commerce Cloud Build Suite** and is a very easy-to-use and highly configurable Jenkins plugin that is used to deploy your builds to your Salesforce Commerce Cloud continuous integration sandbox, development or staging instance. Being a native plugin for Jenkins and not a set of scripts it tightly integrates with it providing the best and easiest to use experience. You can make use of any existing Jenkins plugin (source code management, email notification, reports, etc.), configure it accordingly and use it.

**OSF Builder Suite For Salesforce Commerce Cloud :: Deploy** wants to be the first in a set of plugins that will make your life easier in regards to building your code and deploying it. We have a few ideas for what to build next, but we also take requests into account, so if you think of something you can let us know and we'll take it under consideration for a future plugin.

If you have a bug to report or maybe a feature that you wish to request, please do so [on the project's issues page](https://github.com/jenkinsci/osf-builder-suite-for-sfcc-deploy-plugin/issues).

> **⚠️ Hyperforce migration — action required before September 24, 2026**
>
> The legacy `cert.staging.<realm>.<customer>.demandware.net` hostnames and their server-side certificates
> [expire on September 24, 2026 and will not be renewed](https://developer.salesforce.com/docs/commerce/b2c-commerce/guide/b2c-code-deployment.html).
> On Hyperforce there is no separate hostname for code uploads: you deploy to the **standard** Business Manager
> staging hostname (for example `staging-<realm>-<customer>.demandware.net`) and the client certificate is signed by a
> **CA that you generate yourself** and upload to eCDN — Salesforce no longer issues a `Certificate.zip` for these realms.
>
> If your jobs still point at a `cert.staging.*` hostname, see [Client certificates for secure code uploads (Hyperforce)](#client-certificates-for-secure-code-uploads-hyperforce)
> and update both the `hostname` field and the `OSF Builder Suite :: Two Factor Auth Credentials` entry.

# Features

- Simple. It does one thing, and it does it well.
- Easy to install, use and keep updated.
- Easy to configure. The plugin can be configured from the Jenkins web interface.
- Support for classical mode, Jenkins [Pipelines](https://jenkins.io/doc/book/pipeline/)and also the new modern [Blue Ocean](https://jenkins.io/doc/book/blueocean/) interface.
- Super flexible. Every little thing is configurable so that the plugin can be easily adjusted to your workflow.
- Integrated with the Jenkins [credentials plugin](https://plugins.jenkins.io/credentials) so that your credentials are safely stored encrypted.
- Support for two factor authentication, on both Hyperforce realms (client certificates signed by your own CA, uploaded to eCDN) and legacy realms (client certificates signed with the Salesforce-provided `Certificate.zip`).
- Build info cartridge. A inf_build cartridge will be created as part of the build process that can be used to display information about the build number, version, when the build was made and who made it, in the storefront. This information can be displayed in the page source, title or by using the [OSF Builder Suite For Salesforce Commerce Cloud :: Deploy](https://chrome.google.com/webstore/detail/osf-builder-suite-for-sfc/epdbcbegecijepmdpnhogmedieghhbjj) plugin for Chrome.
- Support for builds bigger than 100MB. The build is split into multiple parts that are deployed one by one so you don't hit the 100MB upload quota limit that Salesforce Commerce Cloud has.
- Good documentation. Every option is documented both here on this page but also inline in Jenkins's UI by clicking the question mark icon next to the item for which you wish to display the help information.
- Support for HTTP proxy with basic or [NTLM](https://en.wikipedia.org/wiki/NT_LAN_Manager) authentication.
- Free
- Open source

# Installation

Just go to `Manage Jenkins > Manage Plugins > Available`, search for `OSF Builder Suite`, select `OSF Builder Suite For Salesforce Commerce Cloud :: Deploy` and click `Download now and install after restart` button.

# Configuration

![](imgs/hostname.png)

Hostname of the SFCC instance where this build should be deployed. Examples:

|                                              |                                                                                                                              |
| -------------------------------------------: | :---------------------------------------------------------------------------------------------------------------------------- |
|      `staging-realm-customer.demandware.net` | For deployments to a staging instance. On **Hyperforce** this is also the hostname used for code uploads that require a client certificate — select your Two Factor Auth credentials alongside it. On legacy realms this form is used only when the instance does **not** have two factor auth enabled. |
| `cert.staging.realm.customer.demandware.net` | **Legacy (non-Hyperforce) only.** For deployments to a staging instance that has two factor auth enabled. This hostname is deactivated on Hyperforce and expires September 24, 2026. |
|  `development-realm-customer.demandware.net` | For deployments to a development instance.                                                                                   |
|        `devNN-realm-customer.demandware.net` | For deployments to a sandbox instance.                                                                                       |

Note that the same hostname value now means different things depending on whether your realm has migrated. On Hyperforce, regular Business Manager login over the standard staging hostname does not require a client certificate, but **code uploads and the related WebDAV operations do** — so a build that authenticates fine interactively can still fail from Jenkins if the Two Factor Auth credentials are set to `- none -`.

![](imgs/tf_credentials.png)

Two Factor Auth credentials of type `OSF Builder Suite :: Two Factor Auth Credentials` for the SFCC instance where this build should be deployed. Select `- none -` only if you deploy to an instance that does not require a client certificate for code uploads (typically a sandbox or development instance).

- **Hyperforce realms** — a client certificate signed by a CA that you generated and uploaded to eCDN. See [Client certificates for secure code uploads (Hyperforce)](#client-certificates-for-secure-code-uploads-hyperforce).
- **Legacy realms** — a client certificate signed with the `{<name>}.crt` / `{<name>}.key` pair from the `Certificate.zip` that Salesforce provided with your realm. See the [legacy procedure](https://developer.salesforce.com/docs/commerce/b2c-commerce/guide/b2c-code-deployment.html) in the Salesforce documentation.

Client certificates expire. Set a calendar reminder a couple of weeks before the `-days` value you chose so the build doesn't start failing unannounced, and remember that on Hyperforce the signing CA itself is capped at 365 days.

![](imgs/oc_credentials.png)

Open Commerce API credentials of type `OSF Builder Suite :: Open Commerce API Credentials` for the SFCC instance where this build should be deployed.

For an automated client such as Jenkins, the first authentication factor is an Account Manager authorization token obtained for a Client ID (see [OCAPI OAuth 2.0](https://developer.salesforce.com/docs/commerce/b2c-commerce/references/b2c-commerce-ocapi/oauth.html)); the client certificate configured above is always the second factor.

![](imgs/oc_version.png)

The version to be used by the calls made to OCAPI. The Open Commerce API Version starts with the character `v` (lowercase) followed by the actual version number, separated by an underscore.

For example: `v19_10`

![](imgs/build_version.png)

Name of the code version that is being deployed. This will be added as a suffix to the one generated by the builder.

Example: If you set it to dev then the code version will be `bN_YYYYMMDD_dev` with N the number of the current build, `YYYY` four digits year, `MM` two digits month, `DD` two digits day and dev at the end.

![](imgs/inf_cartridge.png)

When this option is checked, a new cartridge named inf_build will be created. This cartridge can be used to display information about the build number, version, when the build was made and who made it, in the storefront.

This information can be displayed in the page source, title or by using the [OSF Builder Suite For Salesforce Commerce Cloud :: Deploy](https://chrome.google.com/webstore/detail/osf-builder-suite-for-sfc/epdbcbegecijepmdpnhogmedieghhbjj) plugin for Chrome.

![](imgs/activate_build.png)

When this option is checked, the build will also be activated after it was deployed. If left unchecked the build will only be deployed to the target instance without being activated.

![](imgs/sources.png)

List of sources where the builder will look for cartridges in the form of a path (relative to the workspace) to a directory where the builder will look for cartridges.

Example: `scm/my-git-repo/cartridges`

You can also define a list of patterns to be ignored. If a path matches any of the patterns in this list then it will be ignored and not added to the build. The pattern needs to be relative to the source path defined above.

When a path is matched against a pattern, the following special characters can be used:

|      |                                                                 |
| ---: | --------------------------------------------------------------- |
|  `?` | Matches one character (any character except path separators)    |
|  `*` | Matches zero or more characters (not including path separators) |
| `**` | Matches zero or more path segments                              |

Examples:

|                        |                                                                                                                                  |
| ---------------------: | -------------------------------------------------------------------------------------------------------------------------------- |
|              `**/*.js` | Matches all .js files/dirs in a directory tree                                                                                   |
|      `node_modules/**` | Matches the node_modules folder and all its contents                                                                             |
|          `test/a??.js` | Matches all files/dirs which start with an a, then two more characters and then .js, in a directory called test                  |
|                   `**` | Matches everything in a directory tree                                                                                           |
|      `**/test/**/XYZ*` | Matches all files/dirs which start with XYZ and where there is a parent directory called test (e.g. abc/test/def/ghi/XYZ123)     |

![](imgs/tmp_dir.png)

Path (relative to the workspace) to a temp directory, that will be used during the build. If the directory does not exist, it will be created by the builder and it will also be automatically cleaned up before each build.

Example: `tmp/code`

![](imgs/proxy_host.png)

If your Jenkins server sits behind a firewall and does not have direct access to the internet, you can specify the HTTP proxy host in this field to allow Jenkins to connect to the internet trough it.

![](imgs/proxy_port.png)

This field works in conjunction with the proxy host field to specify the HTTP proxy port.

![](imgs/proxy_username.png)

This field works in conjunction with the proxy host field to specify the username used to authenticate with the proxy.

If this proxy requires Microsoft's [NTLM](https://en.wikipedia.org/wiki/NT_LAN_Manager) authentication scheme then the domain name can be encoded within the username by prefixing the domain name followed by a back-slash `\` before the username, e.g `ACME\John Doe`.

![](imgs/proxy_password.png)

This field works in conjunction with the proxy host field to specify the HTTP proxy password.

![](imgs/ssl_validation.png)

When this option is checked, the builder will no longer validate the SSL certificate and hostname of the target instance. This applies to instances using two factor auth as well.

**This has potential security implications so make sure you know what you are doing before enabling this option!**

Note that you rarely need this: the `Server Certificate` of the `Two Factor Auth Credentials` is trusted *in addition to* the certificate authorities that the JVM running the Jenkins node already trusts, so a renewed instance certificate issued by a public CA is picked up automatically. If the node sits behind a TLS intercepting proxy, import the proxy CA certificate into that JVM's trust store rather than disabling validation.

On Hyperforce the standard staging hostname is served through eCDN with a publicly trusted certificate, so the `Server Certificate` field can normally be left empty. It is the *client* certificate that changes, not the server one.


# **Open Commerce API Settings**

Go to `Administration > Site Development > Open Commerce API Settings`, select type `Data`, select context `Global` and add following configuration:

```JSON
{
    "_v": "19.10",
    "clients": [
        {
            "client_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "resources": [
                {
                    "resource_id": "/code_versions/*",
                    "methods": ["put", "patch"],
                    "read_attributes": "(**)",
                    "write_attributes": "(**)"
                },
                {
                    "resource_id": "/jobs/*/executions",
                    "methods": ["post"],
                    "read_attributes": "(**)",
                    "write_attributes": "(**)"
                },
                {
                    "resource_id": "/jobs/*/executions/*",
                    "methods": ["get"],
                    "read_attributes": "(**)",
                    "write_attributes": "(**)"
                }
            ]
        }
    ]
}
```

Go to `Administration > Organization > WebDAV Client Permissions` and add following configuration:

```JSON
{
    "clients": [
        {
            "client_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "permissions": [
                {
                    "path": "/cartridges",
                    "operations": [
                        "read_write"
                    ]
                },
                {
                    "path": "/impex",
                    "operations": [
                        "read_write"
                    ]
                }
            ]
        }
    ]
}

```

These two configurations are unchanged by the Hyperforce migration.

# **Whitelist cert.staging.???.???.demandware.net hostname (legacy realms only)**

Go to `Administration > Sites > Manage Sites > Business Manager - Hostnames` and whitelist `cert.staging.???.???.demandware.net`

**This step does not apply to Hyperforce.** There is no separate code-upload hostname there — deployments go to the standard Business Manager staging hostname, which is already a valid Business Manager hostname, so nothing extra needs whitelisting.


# Client certificates for secure code uploads (Hyperforce)

Adapted for Jenkins from [Generate, Sign, and Use Client Certificates for Secure Code Uploads (Hyperforce)](https://developer.salesforce.com/docs/commerce/b2c-commerce/guide/b2c-code-deployment.html).

On Hyperforce you generate your own Certificate Authority, register it with eCDN, and sign one client certificate per consumer — including Jenkins. Salesforce never receives or stores your CA bundle, and both the initial upload and later rotations are self-service. Until your realm has migrated, keep using your existing client certificates with the legacy `cert.staging` hostname.

Salesforce Commerce Cloud does not support client keys shorter than 1024 bits; use 2048 bits or more throughout. The CA certificate bundle is capped at **365 days** of validity.

## 1. Generate your CA certificate and private key

Align `${CERT_HOST}` with your staging hostname and use the same value for the certificate's **Common Name**. Leave the challenge password and optional company name blank.

```bash
CERT_HOST=staging-<realm>-<customer>.demandware.net

openssl req -new -newkey rsa:2048 -sha256 -days 365 -x509 -nodes \
    -keyout ${CERT_HOST}.key \
    -out ${CERT_HOST}.crt
```

This produces `${CERT_HOST}.key` (the CA private key — treat it like any other production secret) and `${CERT_HOST}.crt` (the CA certificate). Both are uploaded to eCDN in the next step.

## 2. Upload the CA certificate to eCDN

**Option 1 — Business Manager.** Log in to Business Manager on the **staging** instance, go to `Administration > Site Development > Code Upload Certificate`, click `Add Certificate`, give it a name, then paste the contents of the `.crt` and `.key` files into the `Certificate` and `Private Key` fields and save. Once saved, eCDN accepts any client certificate signed by that CA. Unused, expired or compromised CAs can be deleted from the same page.

**Option 2 — CDN API.** The API expects the PEM contents as single-line JSON strings with literal `\n` where the line breaks were:

```bash
cat ${CERT_HOST}.crt | perl -pe 's/\n/\\n/g'
cat ${CERT_HOST}.key | perl -pe 's/\n/\\n/g'
```

Get an access token for an API client whose allowed scopes include `sfcc.cdn-zones` and `sfcc.cdn-zones.rw`:

```bash
curl "https://account.demandware.com/dwsso/oauth2/access_token" \
    --request POST \
    --user "<api_client_id>:<client_secret>" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --data "grant_type=client_credentials" \
    --data-urlencode "scope=SALESFORCE_COMMERCE_API:<realm>_stg sfcc.cdn-zones.rw"
```

Then create the certificate:

```bash
curl --location "https://<shortcode>.api.commercecloud.salesforce.com/cdn/zones/v1/organizations/f_ecom_<realmid>_stg/mtls/code-upload-certificates" \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer <access_token>" \
    --data '{
        "name": "client ca for jenkins code upload",
        "certificate": "-----BEGIN CERTIFICATE-----\n<certificate_pem_with_literal_newlines>\n-----END CERTIFICATE-----",
        "privateKey": "-----BEGIN PRIVATE KEY-----\n<private_key_pem_with_literal_newlines>\n-----END PRIVATE KEY-----"
    }'
```

A `GET` on the same URL lists the registered certificates together with their `mtlsCertificateId`, and a `DELETE` on `.../code-upload-certificates/<mtlsCertificateId>` removes one.

## 3. Create a client certificate request for Jenkins

Issue a certificate per consumer rather than sharing one, so a single compromised or expired certificate can be replaced without disturbing everyone else. For a human the recommended common name is their Business Manager username; for CI, name it after the Jenkins instance or job that uses it (for example `jenkins-ci-01`).

```bash
openssl req -new -sha256 -newkey rsa:2048 -nodes \
    -out jenkins-ci-01.req \
    -keyout jenkins-ci-01.key
```

Provide location, name and email when prompted; leave the challenge password and optional company name blank.

## 4. Sign the client certificate with your CA

```bash
openssl x509 -CA ${CERT_HOST}.crt -CAkey ${CERT_HOST}.key -CAcreateserial \
    -req -in jenkins-ci-01.req \
    -out jenkins-ci-01.pem \
    -days 365
```

`-CAcreateserial` creates or updates a serial file (`${CERT_HOST}.srl`); if you already keep one, use `-CAserial ${CERT_HOST}.srl` instead. OpenSSL prompts for the CA key passphrase if you set one.

## 5. Export the signed certificate to PKCS#12

```bash
openssl pkcs12 -export -legacy \
    -in jenkins-ci-01.pem \
    -inkey jenkins-ci-01.key \
    -certfile ${CERT_HOST}.crt \
    -name "jenkins-ci-01" \
    -out jenkins-ci-01.p12
```

The `-legacy` flag makes newer OpenSSL releases write a `.p12` that older consumers — Mac keychains, and some older JVMs — can still import. If your Jenkins node runs a recent JDK and the plugin rejects the file, try the export again without `-legacy`. Choose an export password when prompted; you'll need it in the next step.

## 6. Add the certificate to Jenkins

Go to `Manage Jenkins > Credentials`, add a credential of kind `OSF Builder Suite :: Two Factor Auth Credentials`, upload `jenkins-ci-01.p12`, and enter the export password. Reference that credential's ID from the `tfCredentialsId` parameter, and point `hostname` at your standard staging hostname.

Keep the `.p12`, the client key and the CA key out of the repository and off the build workspace — Jenkins stores the credential encrypted, which is the only copy the build needs.

## 7. Rotate or renew the CA

Because the CA is capped at one year, plan the rotation before it lapses; follow the same steps immediately if the CA key or any certificate signed by it may have been exposed.

1. Generate a new self-signed CA and upload it through Business Manager or the CDN API.
2. Several CA bundles can be active at once, so leave the old one in place during the transition.
3. Re-issue and re-sign each client certificate against the new CA (steps 3 to 5), then update the corresponding Jenkins credential.
4. Once every consumer has switched and uploads are confirmed working, delete the old CA from the `Code Upload Certificate` page or via the API `DELETE` endpoint.


# Jenkins Pipeline Configuration

Here's a sample pipeline configuration to get you started:

```Groovy
node {
    stage('Cleanup') {
        cleanWs()
    }

    stage('Git') {
        dir('scm/github.com/???/???') {
            git(
                branch: '???',
                credentialsId: '???',
                url: 'git@github.com:???/???.git'
            )
        }
    }

    stage('Yarn') {
        dir('scm/github.com/???/???') {
            nodejs('NodeJS v12') {
                sh('yarn install')
            }
        }
    }

    stage('Build') {
        dir('scm/github.com/???/???') {
            nodejs('NodeJS v12') {
                sh('yarn run webpack:prd')
            }
        }
    }

    stage('CodePush') {
        osfBuilderSuiteForSFCCDeploy(
            // Hyperforce: the standard staging hostname, e.g. 'staging-na01-customer.demandware.net'
            // Legacy realms with two factor auth: 'cert.staging.realm.customer.demandware.net'
            hostname: '???',
            tfCredentialsId: '???',
            ocCredentialsId: '???',
            ocVersion: 'v19_10',
            buildVersion: 'dev',
            sourcePaths: [[sourcePath: 'scm/github.com/???/???/cartridges']],
            activateBuild: true,
            createBuildInfoCartridge: true,
            tempDirectory: 'tmp/code'
        )
    }

    /* See https://plugins.jenkins.io/osf-builder-suite-for-sfcc-data-import
    stage('DataPush') {
        osfBuilderSuiteForSFCCDataImport(
            hostname: '???',
            tfCredentialsId: '???',
            ocCredentialsId: '???',
            ocVersion: 'v19_10',
            archiveName: 'metadata',
            sourcePath: 'scm/github.com/???/???/metadata',
            importStrategy: 'DELTA',
            tempDirectory: 'tmp/data'
        )
    }
    */
}
```

You can also always consult the pipelines documentation available at <https://jenkins.io/doc/book/pipeline/> or check the pipeline syntax link right inside Jenkins on the left navigation menu.

![](imgs/left_nav.png)

# Version history

<https://github.com/jenkinsci/osf-builder-suite-for-sfcc-deploy-plugin/releases>

# FAQ
* Q: Why am I getting the `InvalidHostHeaderException` while the plugin is making an OCAPI request?
* A: On a legacy realm, go to `Administration >  Sites >  Manage Sites > Business Manager - Hostnames` and whitelist `cert.staging.???.???.demandware.net`. On Hyperforce this error usually means the job is still pointing at the retired `cert.staging` hostname — switch it to the standard staging hostname instead.

* Q: My builds worked until the realm was migrated to Hyperforce, and now the code upload is rejected. What changed?
* A: Two things. The hostname moved from `cert.staging.<realm>.<customer>.demandware.net` to the standard `staging-<realm>-<customer>.demandware.net`, and the client certificate must now be signed by a CA you generated and uploaded to eCDN rather than by the Salesforce-provided `Certificate.zip`. Work through [Client certificates for secure code uploads (Hyperforce)](#client-certificates-for-secure-code-uploads-hyperforce) and update the Jenkins credential.

* Q: The standard staging hostname lets me into Business Manager without a certificate. Do I still need the Two Factor Auth credentials in Jenkins?
* A: Yes. On Hyperforce the client certificate is required for code uploads and the related WebDAV operations even though interactive Business Manager login isn't gated by it.

* Q: I get a `ca key too small` error when uploading the pkcs12 file.
* A: The signing key is below the supported length. Use at least 2048 bits for both the CA and the client certificate. On a legacy realm this can also mean the `Certificate.zip` itself is too old, in which case request a fresh one from Salesforce Customer Support.

* Q: The CDN API returns 401 or 403 when I try to register the CA.
* A: Check that the API client's allowed scopes include `sfcc.cdn-zones` and `sfcc.cdn-zones.rw`, and re-verify the client ID, secret and token request.

* Q: The CDN API says the certificate can't be parsed.
* A: Recheck the PEM-to-JSON conversion — the body needs literal `\n` sequences and nothing else. Confirm the certificate and key are a matching pair using the original PEM files rather than the JSON-escaped versions.

# Dev
- `mvn hpi:run`
- `mvn clean package hpi:hpi`
- `mvn release:prepare release:perform`
