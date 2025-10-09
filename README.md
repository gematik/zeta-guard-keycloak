<img align="right" width="250" height="47" src="docs/img/Gematik_Logo_Flag.png"/> <br/>

# 𝝵-Guard :: Keycloak plugins

Collection of Keycloak plugins and extensions for 𝝵-Guard

# Required tooling

* Java JDK 21
* Docker
* [ktfmt](https://plugins.jetbrains.com/plugin/14912-ktfmt) (IntelliJ IDEA plugin)
* `SonarQube for IDE` (IntelliJ IDEA plugin)

# How to build Keycloak

To build the project, run:

```shell
    ./mvnw clean install
```

# How to run Keycloak

To run the application, you can use the following command in the _runtime/_ directory:

```shell
    docker compose up -d
```

and

```shell
    docker compose down -v
```

respectively.

The Keycloak-Frontend should be then available at http://localhost:18080.

# How to run integration tests

For a build including the integration tests, use:

```shell
    ./mvnw clean install -P integration-tests
```

If the integration tests fail to start any containers, try running `docker compose down -v` in the _runtime/_ directory first.

# Formatting and linting

This project relies on [ktfmt](https://github.com/facebook/ktfmt) for formatting Kotlin source
code. It is recommended to install the [ktfmt](https://plugins.jetbrains.com/plugin/14912-ktfmt) plugin for immediate
correction and feedback while coding.
After installing the plugin, there is a new setting branch under Editor. Enable ktfmt there and select "kotlinlang" as
code style.

ktfmt registers into the IntelliJ Formatter system, so you can continue to use Ctrl-Alt-Shift-l/Cmd-Option-Shift-l, or
use the IDEs auto-save actions,
and so on.

Also, [spotless](https://github.com/diffplug/spotless/tree/main/plugin-maven) will format and lint the source code every
time it is built to catch any drift.

## SonarQube

Use [SonarQube for IDE](https://docs.sonarsource.com/sonarqube-for-ide/intellij/) for additional linting. IntelliJ IDEA
will prompt you to install the plugin if it is missing when you open the project. If you use another supported IDE, you
need to install it manually.

SonarQube is intended to be used
in [connected mode](https://docs.sonarsource.com/sonarqube-for-ide/intellij/team-features/connected-mode/).
Connected mode will align the Sonar configuration across developer systems and CI pipelines and enable additional
features.
You need to connect to a SonarQube server and bind to a project.

SonarQube is also integrated into the CI pipeline and serves as a quality gate for builds.
Reports can be accessed using links in the individual pipeline logs.

## License

(C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH

Apache License, Version 2.0

See the [LICENSE](./LICENSE) for the specific language governing permissions and limitations under the License

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for use. These are regularly typical conditions in connection with open source or free software. Programs described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
    1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial portions of the Software.
    2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising from, out of or in connection with the software or the use or other dealings with the software, whether in an action of contract, tort, or otherwise.
    3. We take open source license compliance very seriously. We are always striving to achieve compliance at all times and to improve our processes. If you find any issues or have any suggestions or comments, or if you see any other ways in which we can improve, please reach out to: ospo@gematik.de
3. Please note: Parts of this code may have been generated using AI-supported technology. Please take this into account, especially when troubleshooting, for security analyses and possible adjustments.
