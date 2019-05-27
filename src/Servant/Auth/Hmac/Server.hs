{-# LANGUAGE DataKinds    #-}
{-# LANGUAGE TypeFamilies #-}

-- | Servant server authentication.

module Servant.Auth.Hmac.Server
       ( HmacAuth
       , HmacAuthContextHandlers
       , HmacAuthContext
       , HmacAuthHandler
       , hmacAuthServerContext
       , hmacAuthHandler
       , hmacAuthHandlerMap
       ) where

import Control.Monad.Except (throwError)
import Data.ByteString (ByteString)
import Data.Maybe (fromMaybe)
import Network.Wai (rawPathInfo, rawQueryString, requestHeaderHost, requestHeaders, requestMethod)
import Servant (Context ((:.), EmptyContext))
import Servant.API (AuthProtect)
import Servant.Server (Handler, err401, errBody)
import Servant.Server.Experimental.Auth (AuthHandler, AuthServerData, mkAuthHandler)

import Servant.Auth.Hmac.Crypto (RequestPayload (..), SecretKey, Signature, keepWhitelistedHeaders,
                                 verifySignatureHmac)

import qualified Network.Wai as Wai (Request)


type HmacAuth = AuthProtect "hmac-auth"

type instance AuthServerData HmacAuth = ()

type HmacAuthHandler = AuthHandler Wai.Request ()
type HmacAuthContextHandlers = '[HmacAuthHandler]
type HmacAuthContext = Context HmacAuthContextHandlers

hmacAuthServerContext
    :: (SecretKey -> ByteString -> Signature)  -- ^ Signing function
    -> SecretKey  -- ^ Secret key that was used for signing 'Request'
    -> HmacAuthContext
hmacAuthServerContext signer sk = hmacAuthHandler signer sk :. EmptyContext

-- | Create 'HmacAuthHandler' from signing function and secret key.
hmacAuthHandler
    :: (SecretKey -> ByteString -> Signature)  -- ^ Signing function
    -> SecretKey  -- ^ Secret key that was used for signing 'Request'
    -> HmacAuthHandler
hmacAuthHandler = hmacAuthHandlerMap pure

{- | Like 'hmacAuthHandler' but allows to specify additional mapping function
for 'Wai.Request'. This can be useful if you want to print incoming request (for
logging purposes) or filter some headers (to match signature). Given function is
applied before signature verification.
-}
hmacAuthHandlerMap
    :: (Wai.Request -> Handler Wai.Request)  -- ^ Request mapper
    -> (SecretKey -> ByteString -> Signature)  -- ^ Signing function
    -> SecretKey  -- ^ Secret key that was used for signing 'Request'
    -> HmacAuthHandler
hmacAuthHandlerMap mapper signer sk = mkAuthHandler handler
  where
    handler :: Wai.Request -> Handler ()
    handler req = do
        newReq <- mapper req
        let payload = waiRequestToPayload newReq
        let verification = verifySignatureHmac signer sk payload
        case verification of
            Nothing -> pure ()
            Just bs -> throwError $ err401 { errBody = bs }

----------------------------------------------------------------------------
-- Internals
----------------------------------------------------------------------------

-- getWaiRequestBody :: Wai.Request -> IO ByteString
-- getWaiRequestBody request = BS.concat <$> getChunks
--   where
--     getChunks :: IO [ByteString]
--     getChunks = requestBody request >>= \chunk ->
--         if chunk == BS.empty
--         then pure []
--         else (chunk:) <$> getChunks

waiRequestToPayload :: Wai.Request -> RequestPayload
-- waiRequestToPayload req = getWaiRequestBody req >>= \body -> pure RequestPayload
waiRequestToPayload req = RequestPayload
    { rpMethod  = requestMethod req
    , rpContent = ""
    , rpHeaders = keepWhitelistedHeaders $ requestHeaders req
    , rpRawUrl  = fromMaybe mempty (requestHeaderHost req) <> rawPathInfo req <> rawQueryString req
    }
