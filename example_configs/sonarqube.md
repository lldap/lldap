# Configuring LDAP in SonarQube

[SonarQube](https://github.com/SonarSource/sonarqube)

Continuous Inspection

---

SonarQube can configure ldap through environment variables when deploying using docker-compose

## docker-compose.yaml

```yaml
version: "3"

services:
  sonarqube:
    image: sonarqube:community
    depends_on:
      - db
    environment:
      SONAR_JDBC_URL: jdbc:postgresql://db:5432/sonar
      SONAR_JDBC_USERNAME: sonar
      SONAR_JDBC_PASSWORD: sonar
      LDAP_URL: ldap://example.com:3890
      LDAP_BINDDN: cn=admin,ou=people,dc=example,dc=com
      LDAP_BINDPASSWORD: passwd
      LDAP_AUTHENTICATION: simple
      LDAP_USER_BASEDN: ou=people,dc=example,dc=com
      LDAP_USER_REQUEST: (&(objectClass=inetOrgPerson)(uid={login})(memberof=cn=sonarqube_users,ou=groups,dc=example,dc=com))
      LDAP_USER_REALNAMEATTRIBUTE: cn
      LDAP_USER_EMAILATTRIBUTE: mail
    volumes:
      - sonarqube_data:/opt/sonarqube/data
      - sonarqube_extensions:/opt/sonarqube/extensions
      - sonarqube_logs:/opt/sonarqube/logs
    ports:
      - "9000:9000"
  db:
    image: postgres:12
    environment:
      POSTGRES_USER: sonar
      POSTGRES_PASSWORD: sonar
    volumes:
      - postgresql:/var/lib/postgresql
      - postgresql_data:/var/lib/postgresql/data

volumes:
  sonarqube_data:
  sonarqube_extensions:
  sonarqube_logs:
  postgresql:
  postgresql_data:
```

> [SonarQube docker-compose.yaml example](https://docs.sonarsource.com/sonarqube/latest/setup-and-upgrade/install-the-server/installing-sonarqube-from-docker/)

