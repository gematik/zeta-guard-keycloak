# Integration Tests

This module contains the integration tests for the 𝝵-Guard Keycloak plugins. These tests verify the end-to-end
functionality of the custom extensions by running them inside a real Keycloak server instance.

## Technologies Used

The integration test suite is built upon:

* **[Testcontainers](https://www.testcontainers.org/)**: Manages the lifecycle of Docker containers required for the
  tests. It programmatically starts and stops Keycloak and other containers.
* **Keycloak Admin Client**: A Java client library that allows interaction with the Keycloak server's Admin REST API.
* **kotest**: The primary testing framework used to structure and execute the tests.

## Running the Tests

The integration tests are not run by default to speed up the normal build process. They are activated using a specific
Maven profile.

To build the project and execute the integration tests, run the following command from the project's root directory:

```bash
    mvn clean install -Pintegration-tests
```
