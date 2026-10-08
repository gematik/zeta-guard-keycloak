/*-
 * #%L
 * keycloak-zeta
 * %%
 * (C) tech@Spree GmbH, 2026, licensed for gematik GmbH
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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement.userinfo

import jakarta.ws.rs.GET
import jakarta.ws.rs.Produces
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response

const val USERINFO_STATIC_EMAIL = "max.mustermann@example.de"

class UserInfoEmailResource {

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  fun getEmail(@QueryParam("id") id: String?): Response {
    if (id.isNullOrBlank()) {
      return Response.status(Response.Status.NOT_FOUND).build()
    }

    // MS5b: implement this endpoint and return correct email
    return Response.ok(UserInfoEmailResponse(USERINFO_STATIC_EMAIL)).build()
  }
}
