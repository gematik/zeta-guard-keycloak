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

import jakarta.persistence.SharedCacheMode
import jakarta.persistence.ValidationMode
import jakarta.persistence.spi.ClassTransformer
import jakarta.persistence.spi.PersistenceUnitInfo
import jakarta.persistence.spi.PersistenceUnitTransactionType
import java.net.URL
import java.util.Properties
import javax.sql.DataSource
import org.hibernate.jpa.HibernatePersistenceProvider

class HibernatePersistenceUnitInfo(
    private val persistenceUnitName: String,
    private val managedClassNames: Set<String>,
    private val properties: Properties,
) : PersistenceUnitInfo {
  override fun getPersistenceUnitName() = persistenceUnitName

  override fun getPersistenceProviderClassName(): String = HibernatePersistenceProvider::class.java.simpleName

  override fun getTransactionType() = PersistenceUnitTransactionType.RESOURCE_LOCAL

  override fun getJtaDataSource(): DataSource? = null

  override fun getNonJtaDataSource(): DataSource? = null

  override fun getMappingFileNames() = listOf<String>()

  override fun getJarFileUrls() = listOf<URL>()

  override fun getPersistenceUnitRootUrl() = null

  override fun getManagedClassNames() = ArrayList(managedClassNames)

  override fun excludeUnlistedClasses() = true

  override fun getSharedCacheMode() = SharedCacheMode.DISABLE_SELECTIVE

  override fun getValidationMode() = ValidationMode.AUTO

  override fun getProperties() = properties

  override fun getPersistenceXMLSchemaVersion() = jpaVersion

  override fun getClassLoader(): ClassLoader = ClassLoader.getSystemClassLoader()

  override fun addTransformer(transformer: ClassTransformer): Unit = throw UnsupportedOperationException()

  override fun getNewTempClassLoader() = null

  companion object {
    var jpaVersion: String = "2.1"
  }
}
