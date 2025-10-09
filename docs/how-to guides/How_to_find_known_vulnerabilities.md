# How to find known vulnerabilities in this codebase using OWASP dependency check

```shell
./mvnw org.owasp:dependency-check-maven:aggregate
open target/dependency-check-report.html
```

To use an [NVD API key](https://nvd.nist.gov/developers/start-here), set the environment variable `NVD_API_KEY`.
