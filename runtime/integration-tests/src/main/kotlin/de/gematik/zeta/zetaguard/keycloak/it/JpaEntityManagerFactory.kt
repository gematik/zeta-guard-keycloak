/*-
 * #%L
 * keycloak-zeta
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */
package de.gematik.zeta.zetaguard.keycloak.it

import jakarta.persistence.EntityManager
import jakarta.persistence.EntityManagerFactory
import org.hibernate.cfg.CacheSettings.USE_QUERY_CACHE
import org.hibernate.cfg.CacheSettings.USE_SECOND_LEVEL_CACHE
import org.hibernate.cfg.JdbcSettings.DIALECT
import org.hibernate.cfg.JdbcSettings.FORMAT_SQL
import org.hibernate.cfg.JdbcSettings.JAKARTA_JDBC_DRIVER
import org.hibernate.cfg.JdbcSettings.JAKARTA_JDBC_PASSWORD
import org.hibernate.cfg.JdbcSettings.JAKARTA_JDBC_URL
import org.hibernate.cfg.JdbcSettings.JAKARTA_JDBC_USER
import org.hibernate.cfg.JdbcSettings.SHOW_SQL
import org.hibernate.jpa.boot.internal.EntityManagerFactoryBuilderImpl
import org.hibernate.jpa.boot.internal.PersistenceUnitInfoDescriptor

@Suppress("unused")
class JpaEntityManagerFactory(host: String, port: Int, vararg entityClasses: Class<*>) :
    AutoCloseable {
    private lateinit var entityManagerFactory: EntityManagerFactory
    private val entityClasses =
        entityClasses.map<Class<*>, String> { obj: Class<*> -> obj.getName() }.toSet()
    var debugSQL = false

    private val properties: Map<String, String> =
        mapOf(
            DIALECT to "org.hibernate.dialect.PostgreSQLDialect",
            JAKARTA_JDBC_DRIVER to "org.postgresql.Driver",
            JAKARTA_JDBC_URL to "jdbc:postgresql://$host:$port/keycloak?ssl=false",
            JAKARTA_JDBC_USER to "zeta-guard",
            JAKARTA_JDBC_PASSWORD to "geheim",
            SHOW_SQL to debugSQL.toString(),
            FORMAT_SQL to debugSQL.toString(),
            USE_SECOND_LEVEL_CACHE to "false",
            USE_QUERY_CACHE to "false",
        )

    fun createEntityManager(): EntityManager = getEntityManagerFactory().createEntityManager()

    fun getEntityManagerFactory(): EntityManagerFactory {
        if (!this::entityManagerFactory.isInitialized || !entityManagerFactory.isOpen) {
            val persistenceUnitInfo =
                HibernatePersistenceUnitInfo(
                    javaClass.getSimpleName(),
                    entityClasses,
                    properties.toProperties(),
                )
            val builder =
                EntityManagerFactoryBuilderImpl(
                    PersistenceUnitInfoDescriptor(persistenceUnitInfo),
                    properties,
                )

            entityManagerFactory = builder.build()
        }

        return entityManagerFactory
    }

    fun shutdown() {
        if (this::entityManagerFactory.isInitialized && entityManagerFactory.isOpen) {
            entityManagerFactory.close()
        }
    }

    override fun close() {
        shutdown()
    }
}
