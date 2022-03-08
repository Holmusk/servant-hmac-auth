{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeFamilies #-}

-- | Servant server authentication.
module Servant.Auth.Hmac.Server (
    HmacAuth,
    HmacAuthContextHandlers,
    HmacAuthContext,
    HmacAuthHandler,
    hmacAuthServerContext,
    hmacAuthHandler,
    hmacAuthHandlerMap,
) where

import Control.Monad.Except (throwError)
import Data.ByteString (ByteString)
import qualified Network.Wai as Wai (Request)
import Servant (Context (EmptyContext, (:.)))
import Servant.API (AuthProtect)
import Servant.Auth.Hmac.Crypto (
    SecretKey,
    Signature,
    verifySignatureHmac,
 )
import Servant.Auth.Hmac.Internal (waiRequestToPayload)
import Servant.Server (Handler, err401, errBody)
import Servant.Server.Experimental.Auth (AuthHandler, AuthServerData, mkAuthHandler)

type HmacAuth = AuthProtect "hmac-auth"

type instance AuthServerData HmacAuth = ()

type HmacAuthHandler = AuthHandler Wai.Request ()
type HmacAuthContextHandlers = '[HmacAuthHandler]
type HmacAuthContext = Context HmacAuthContextHandlers

hmacAuthServerContext ::
    -- | Signing function
    (SecretKey -> ByteString -> Signature) ->
    -- | Secret key that was used for signing 'Request'
    SecretKey ->
    HmacAuthContext
hmacAuthServerContext signer sk = hmacAuthHandler signer sk :. EmptyContext

-- | Create 'HmacAuthHandler' from signing function and secret key.
hmacAuthHandler ::
    -- | Signing function
    (SecretKey -> ByteString -> Signature) ->
    -- | Secret key that was used for signing 'Request'
    SecretKey ->
    HmacAuthHandler
hmacAuthHandler = hmacAuthHandlerMap pure

{- | Like 'hmacAuthHandler' but allows to specify additional mapping function
for 'Wai.Request'. This can be useful if you want to print incoming request (for
logging purposes) or filter some headers (to match signature). Given function is
applied before signature verification.
-}
hmacAuthHandlerMap ::
    -- | Request mapper
    (Wai.Request -> Handler Wai.Request) ->
    -- | Signing function
    (SecretKey -> ByteString -> Signature) ->
    -- | Secret key that was used for signing 'Request'
    SecretKey ->
    HmacAuthHandler
hmacAuthHandlerMap mapper signer sk = mkAuthHandler handler
  where
    handler :: Wai.Request -> Handler ()
    handler req = do
        newReq <- mapper req
        let payload = waiRequestToPayload newReq ""
        let verification = verifySignatureHmac signer sk payload
        case verification of
            Nothing -> pure ()
            Just bs -> throwError $ err401{errBody = bs}
