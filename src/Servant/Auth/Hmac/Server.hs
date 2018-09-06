{-# LANGUAGE DataKinds    #-}
{-# LANGUAGE TypeFamilies #-}

module Servant.Auth.Hmac.Server
       ( HmacAuth
       , HmacAuthContextHandlers
       , HmacAuthContext
       , hmacAuthServerContext
       , hmacAuthHandler
       ) where

import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Data.ByteString (ByteString)
import Data.Maybe (fromMaybe)
import Network.Wai (rawPathInfo, rawQueryString, requestBody, requestHeaderHost, requestHeaders,
                    requestMethod)
import Servant (Context ((:.), EmptyContext))
import Servant.API (AuthProtect)
import Servant.Server (Handler, err401, errBody)
import Servant.Server.Experimental.Auth (AuthHandler, AuthServerData, mkAuthHandler)

import Servant.Auth.Hmac.Crypto (RequestPayload (..), SecretKey, Signature, verifySignatureHmac)

import qualified Data.ByteString as BS
import qualified Network.Wai as Wai (Request)

----------------------------------------------------------------------------
-- Servant auth
----------------------------------------------------------------------------

type HmacAuth = AuthProtect "hmac-auth"

type instance AuthServerData HmacAuth = ()

type HmacAuthContextHandlers = '[AuthHandler Wai.Request ()]
type HmacAuthContext = Context HmacAuthContextHandlers

hmacAuthServerContext
    :: (SecretKey -> ByteString -> Signature)  -- ^ Signing function
    -> SecretKey  -- ^ Secret key that was used for signing 'Request'
    -> HmacAuthContext
hmacAuthServerContext signer sk = hmacAuthHandler signer sk :. EmptyContext

hmacAuthHandler
    :: (SecretKey -> ByteString -> Signature)  -- ^ Signing function
    -> SecretKey  -- ^ Secret key that was used for signing 'Request'
    -> AuthHandler Wai.Request ()
hmacAuthHandler signer sk = mkAuthHandler handler
  where
    handler :: Wai.Request -> Handler ()
    handler req = liftIO (verifySignatureHmac signer sk <$> waiRequestToPayload req) >>= \case
        True  -> pure ()
        False -> throwError $ err401 { errBody = "HMAC Auth failed." }

----------------------------------------------------------------------------
-- Internals
----------------------------------------------------------------------------

getWaiRequestBody :: Wai.Request -> IO ByteString
getWaiRequestBody request = BS.concat <$> getChunks
  where
    getChunks :: IO [ByteString]
    getChunks = requestBody request >>= \chunk ->
        if chunk == BS.empty
        then pure []
        else (chunk:) <$> getChunks

waiRequestToPayload :: Wai.Request -> IO RequestPayload
waiRequestToPayload req = getWaiRequestBody req >>= \body -> pure RequestPayload
    { rpMethod  = requestMethod req
    , rpContent = body
    , rpHeaders = requestHeaders req
    , rpRawUrl  = fromMaybe mempty (requestHeaderHost req) <> rawPathInfo req <> rawQueryString req
    }
