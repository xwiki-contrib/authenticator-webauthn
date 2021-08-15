/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
 (function(root, factory) {
   if (typeof define === 'function' && define.amd) {
     define(['base64url'], factory);
   } else if (typeof module === 'object' && module.exports) {
     module.exports = factory(require('base64url'));
   } else {
     root.webauthn = factory(root.base64url);
   }
 })(this, function(base64url) {

   function extend(obj, more) {
     return Object.assign({}, obj, more);
   }

   /**
    * Create a WebAuthn credential.
    *
    * @param request: object - A PublicKeyCredentialCreationOptions object, except
    *   where binary values are base64url encoded strings instead of byte arrays
    *
    * @return a PublicKeyCredentialCreationOptions suitable for passing as the
    *   `publicKey` parameter to `navigator.credentials.create()`
    */
   function decodePublicKeyCredentialCreationOptions(request) {
     const excludeCredentials = request.excludeCredentials.map(credential => extend(
       credential, {
       id: base64url.toByteArray(credential.id),
     }));

     const publicKeyCredentialCreationOptions = extend(
       request, {
       attestation: 'direct',
       user: extend(
         request.user, {
         id: base64url.toByteArray(request.user.id),
       }),
       challenge: base64url.toByteArray(request.challenge),
       excludeCredentials,
     });

     return publicKeyCredentialCreationOptions;
   }

   /**
    * Create a WebAuthn credential.
    *
    * @param request: object - A PublicKeyCredentialCreationOptions object, except
    *   where binary values are base64url encoded strings instead of byte arrays
    *
    * @return the Promise returned by `navigator.credentials.create`
    */
   function createCredential(request) {
     return navigator.credentials.create({
       publicKey: decodePublicKeyCredentialCreationOptions(request),
     });
   }

   /**
    * Perform a WebAuthn assertion.
    *
    * @param request: object - A PublicKeyCredentialRequestOptions object,
    *   except where binary values are base64url encoded strings instead of byte
    *   arrays
    *
    * @return a PublicKeyCredentialRequestOptions suitable for passing as the
    *   `publicKey` parameter to `navigator.credentials.get()`
    */
   function decodePublicKeyCredentialRequestOptions(request) {
     const allowCredentials = request.allowCredentials && request.allowCredentials.map(credential => extend(
       credential, {
       id: base64url.toByteArray(credential.id),
     }));

     const publicKeyCredentialRequestOptions = extend(
       request, {
       allowCredentials,
       challenge: base64url.toByteArray(request.challenge),
     });

     return publicKeyCredentialRequestOptions;
   }

   /**
    * Perform a WebAuthn assertion.
    *
    * @param request: object - A PublicKeyCredentialRequestOptions object,
    *   except where binary values are base64url encoded strings instead of byte
    *   arrays
    *
    * @return the Promise returned by `navigator.credentials.get`
    */
   function getAssertion(request) {
     console.log('Get assertion', request);
     return navigator.credentials.get({
       publicKey: decodePublicKeyCredentialRequestOptions(request),
     });
   }


   /**
    * Turn a PublicKeyCredential object into a plain object with base64url encoded binary values
    */
   function responseToObject(response) {
     if (response.u2fResponse) {
       return response;
     } else {
       let clientExtensionResults = {};

       try {
         clientExtensionResults = response.getClientExtensionResults();
       } catch (e) {
         console.error('getClientExtensionResults failed', e);
       }

       if (response.response.attestationObject) {
         return {
           type: response.type,
           id: response.id,
           response: {
             attestationObject: base64url.fromByteArray(response.response.attestationObject),
             clientDataJSON: base64url.fromByteArray(response.response.clientDataJSON),
           },
           clientExtensionResults,
         };
       } else {
         return {
           type: response.type,
           id: response.id,
           response: {
             authenticatorData: base64url.fromByteArray(response.response.authenticatorData),
             clientDataJSON: base64url.fromByteArray(response.response.clientDataJSON),
             signature: base64url.fromByteArray(response.response.signature),
             userHandle: response.response.userHandle && base64url.fromByteArray(response.response.userHandle),
           },
           clientExtensionResults,
         };
       }
     }
   }

   return {
     decodePublicKeyCredentialCreationOptions,
     decodePublicKeyCredentialRequestOptions,
     createCredential,
     getAssertion,
     responseToObject,
   };

 });