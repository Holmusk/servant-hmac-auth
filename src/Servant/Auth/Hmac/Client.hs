{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE InstanceSigs        #-}
{-# LANGUAGE ViewPatterns        #-}

-- | Servant client authentication.

module Servant.Auth.Hmac.Client
       ( HmacClientM (..)
       , runHmacClient
       , hmacClient
       ) where

import Control.Monad ((>=>))
import Control.Monad.Reader (MonadReader (..), ReaderT, asks, runReaderT)
import Control.Monad.Trans.Class (lift)
import Data.Binary.Builder (toLazyByteString)
import Data.ByteString (ByteString)
import Data.Proxy (Proxy (..))
import Data.Sequence ((<|))
import Network.HTTP.Client (RequestBody (..))
import Servant.Client (BaseUrl, Client, ClientEnv (baseUrl), ClientM, HasClient, ServantError,
                       runClientM)
import Servant.Client.Core (RunClient (..), clientIn)
import Servant.Client.Internal.HttpClient (requestToClientRequest)

import Servant.Auth.Hmac.Crypto (RequestPayload (..), SecretKey, Signature (..), authHeaderName,
                                 requestSignature)

import qualified Data.ByteString.Lazy as LBS (toStrict)
import qualified Network.HTTP.Client as Client (host, method, path, queryString, requestBody,
                                                requestHeaders)
import qualified Servant.Client.Core as Servant (Request, Response, StreamingResponse,
                                                 requestHeaders)


-- | Environment for 'HmacClientM'.
data HmacSettings = HmacSettings
    { hmacSigner    :: SecretKey -> ByteString -> Signature
    , hmacSecretKey :: SecretKey
    }

{- | @newtype@ wrapper over 'ClientM' that signs all outgoing requests
automatically.
-}
newtype HmacClientM a = HmacClientM
    { runHmacClientM :: ReaderT HmacSettings ClientM a
    } deriving (Functor, Applicative, Monad, MonadReader HmacSettings)

hmacifyClient :: ClientM a -> HmacClientM a
hmacifyClient = HmacClientM . lift


hmacClientSign :: Servant.Request -> HmacClientM Servant.Request
hmacClientSign req = HmacClientM $ do
    HmacSettings{..} <- ask
    url <- lift $ asks baseUrl
    pure $ signRequestHmac hmacSigner hmacSecretKey url req

instance RunClient HmacClientM where
    runRequest :: Servant.Request -> HmacClientM Servant.Response
    runRequest = hmacClientSign >=> hmacifyClient . runRequest

    streamingRequest :: Servant.Request -> HmacClientM Servant.StreamingResponse
    streamingRequest = hmacClientSign >=> hmacifyClient . streamingRequest

    throwServantError :: ServantError -> HmacClientM a
    throwServantError = hmacifyClient . throwServantError

runHmacClient
    :: (SecretKey -> ByteString -> Signature)  -- ^ Signing function
    -> SecretKey  -- ^ Secret key to sign all requests
    -> ClientEnv
    -> HmacClientM a
    -> IO (Either ServantError a)
runHmacClient hmacSigner hmacSecretKey env client =
    runClientM (runReaderT (runHmacClientM client) HmacSettings{..}) env

-- | Generates a set of client functions for an API.
hmacClient :: forall api .  HasClient HmacClientM api => Client HmacClientM api
hmacClient = Proxy @api `clientIn` Proxy @HmacClientM

----------------------------------------------------------------------------
-- Internals
----------------------------------------------------------------------------

servantRequestToPayload :: BaseUrl -> Servant.Request -> RequestPayload
servantRequestToPayload url (requestToClientRequest url -> req) = RequestPayload
    { rpMethod  = Client.method req
    , rpContent = toBsBody $ Client.requestBody req
    , rpHeaders = Client.requestHeaders req
    , rpRawUrl  = Client.host req <> Client.path req <> Client.queryString req
    }
  where
    toBsBody :: RequestBody -> ByteString
    toBsBody (RequestBodyBS bs)       = bs
    toBsBody (RequestBodyLBS bs)      = LBS.toStrict bs
    toBsBody (RequestBodyBuilder _ b) = LBS.toStrict $ toLazyByteString b
    toBsBody _                        = ""  -- heh

{- | Adds signed header to the request.

@
Authentication: HMAC <signature>
@
-}
signRequestHmac
    :: (SecretKey -> ByteString -> Signature)  -- ^ Signing function
    -> SecretKey  -- ^ Secret key that was used for signing 'Request'
    -> BaseUrl  -- ^ Base url for servant request
    -> Servant.Request  -- ^ Original request
    -> Servant.Request  -- ^ Signed request
signRequestHmac signer sk url req = do
    let payload = servantRequestToPayload url req
    let signature = requestSignature signer sk payload
    let authHead = (authHeaderName, "HMAC " <> unSignature signature)
    req { Servant.requestHeaders = authHead <| Servant.requestHeaders req }
