# Installing and Configuring LLDAP on TrueNAS

This guide walks through installing **LLDAP** from the TrueNAS Apps catalog and performing a basic configuration suitable for sharing authentication between multiple applications that support LDAP authentication.

It is intended to accompany the example configuration files in this repository and assumes a basic familiarity with the TrueNAS web interface.

## Prerequisites

- TrueNAS SCALE with Apps enabled
- Administrative access to the TrueNAS UI
- A system with working networking and DNS
- Optional but recommended: HTTPS certificates managed by TrueNAS

## Step 1: Install LLDAP from the TrueNAS Apps Catalog

1. Log in to the **TrueNAS web interface**.
2. Navigate to **Apps → Discover Apps**.
3. Search for **LLDAP**.
4. Click **Install**.

You will be presented with the LLDAP application configuration form.

## Step 2: Application Configuration

Below are the key configuration sections and recommended settings based on the official catalog definition.

### Application Name

- Leave the default name or choose a descriptive one (e.g. `lldap`).

### Networking

- **Web Port**: Default application port is typically **30325**. There is no standard port for the LLDAP web UI; this value is configurable in TrueNAS.
- **LDAP Port**:
  - Standard LDAP port: **389**
  - Default port configured by the TrueNAS app: **30326**
- **LDAPS Port**:
  - Standard LDAPS port: **636**
  - Default port configured by the TrueNAS app: **30327**

It is recommended to adjust these ports to suit your environment. Using standard ports (389/636) can simplify client configuration, but non-standard ports may be preferred to avoid conflicts on the host system. Ensure the selected ports are not already in use.

If LDAPS is enabled, it is strongly recommended to **disable the LDAP port** to ensure all directory traffic is encrypted.

### Authentication / Admin Account

- **LLDAP Admin Username**: Set an admin username (e.g. `admin`).
- **LLDAP Admin Password**: Set a strong password. This account is used to access the LLDAP web UI.

> ⚠️ Save this password securely. You will need it to log in and manage users and groups.

### Base DN Configuration

These values define your LDAP directory structure:

- **Base DN**: Example: `dc=example,dc=com`
- **User DN**: Typically `ou=people,dc=example,dc=com`
- **Group DN**: Typically `ou=groups,dc=example,dc=com`

These values must be consistent with the configuration used by client applications.

## Step 3: Storage Configuration

LLDAP requires persistent storage for its database.

- Configure an **application dataset** or **host path** for LLDAP data.
- Ensure the dataset is backed up as part of your normal TrueNAS backup strategy.

## Step 4: (Optional) Enable HTTPS Using TrueNAS Certificates

If your TrueNAS system manages certificates:

1. In the app configuration, select **Use Existing Certificate**.
2. Choose a certificate issued by TrueNAS.
3. Ensure the web port is accessed via `https://`.

This avoids storing certificate files inside the container and improves overall security.

## Step 5: Deploy the App

1. Review all configuration values.
2. Click **Install**.
3. Wait for the application status to show **Running**.

## Step 6: Access the LLDAP Web UI

- Navigate to: `http(s)://<truenas-ip>:<web-port>`
- Log in using the admin credentials you configured earlier.

From here you can:
- Create users
- Create groups
- Assign users to groups

## Step 7: Using LLDAP with Other Applications

LLDAP can be used as a central identity provider for many popular applications available in the TrueNAS Apps catalog. Common examples include:

- **Jellyfin** (media server)
- **Nextcloud** (collaboration and file sharing)
- **Gitea** (self-hosted Git service)
- **Grafana** (monitoring and dashboards)
- **MinIO** (object storage)

Configuration examples for several of these applications are also available in the upstream LLDAP repository under `example_configs`.

When configuring a client application:

- **LDAP Host**: TrueNAS IP address or the LLDAP app service name
- **LDAP / LDAPS Port**: As configured during install (prefer LDAPS if enabled)
- **Bind DN**: A dedicated service (bind) account or admin DN
- **Bind Password**: Password for the bind account
- **Base DN**: Must match the LLDAP Base DN

Once configured, users can authenticate to multiple applications using a single set of credentials managed centrally by LLDAP.

## Notes and Tips

- Prefer creating a **dedicated bind user** for applications instead of using the admin account.
- Keep Base DN values consistent across all services.
- Back up the LLDAP dataset regularly.

## References

- TrueNAS Apps Catalog: https://apps.truenas.com/catalog/lldap/
- TrueNAS SCALE Documentation: https://www.truenas.com/docs/scale/
