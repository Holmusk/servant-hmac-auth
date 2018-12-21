{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE InstanceSigs        #-}

-- | Servant client authentication.

module Servant.Auth.Hmac.Client
       ( -- * HMAC client settings
         HmacSettings (..)
       , defaultHmacSettings

         -- * HMAC servant client
       , HmacClientM (..)
       , runHmacClient
       , hmacClient
       ) where

import Control.Monad ((>=>))
import Control.Monad.IO.Class (MonadIO (..))
import Control.Monad.Reader (MonadReader (..), ReaderT, asks, runReaderT)
import Control.Monad.Trans.Class (lift)
import Data.Binary.Builder (toLazyByteString)
import Data.ByteString (ByteString)
import Data.Foldable (toList)
import Data.List (sort)
import Data.Proxy (Proxy (..))
import Data.Sequence (fromList, (<|))
import Network.HTTP.Client (RequestBody (..))
import Servant.Client (BaseUrl, Client, ClientEnv (baseUrl), ClientM, HasClient, ServantError,
                       runClientM)
import Servant.Client.Core (RunClient (..), clientIn)
import Servant.Client.Internal.HttpClient (requestToClientRequest)

import Servant.Auth.Hmac.Crypto (RequestPayload (..), SecretKey, Signature (..), authHeaderName,
                                 keepWhitelistedHeaders, requestSignature, signSHA256)

import qualified Data.ByteString.Lazy as LBS (toStrict)
import qualified Network.HTTP.Client as Client
import qualified Servant.Client.Core as Servant


-- | Environment for 'HmacClientM'. Contains all required settings for hmac client.
data HmacSettings = HmacSettings
    { -- | Singing function that will sign all outgoing requests.
      hmacSigner      :: SecretKey -> ByteString -> Signature

      -- | Secret key for signing function.
    , hmacSecretKey   :: SecretKey

      -- | Function to call for every request after this request is signed.
      -- Useful for debugging.
    , hmacRequestHook :: Maybe (Servant.Request -> ClientM ())
    }

{- | Default 'HmacSettings' with the following configuration:

1. Signing function is 'signSHA256'.
2. Secret key is provided.
3. 'hmacRequestHook' is 'Nothing'.
-}
defaultHmacSettings :: SecretKey -> HmacSettings
defaultHmacSettings sk = HmacSettings
    { hmacSigner      = signSHA256
    , hmacSecretKey   = sk
    , hmacRequestHook = Nothing
    }

{- | @newtype@ wrapper over 'ClientM' that signs all outgoing requests
automatically.
-}
newtype HmacClientM a = HmacClientM
    { runHmacClientM :: ReaderT HmacSettings ClientM a
    } deriving (Functor, Applicative, Monad, MonadIO, MonadReader HmacSettings)

hmacifyClient :: ClientM a -> HmacClientM a
hmacifyClient = HmacClientM . lift

hmacClientSign :: Servant.Request -> HmacClientM Servant.Request
hmacClientSign req = HmacClientM $ do
    HmacSettings{..} <- ask
    url <- lift $ asks baseUrl
    let signedRequest = signRequestHmac hmacSigner hmacSecretKey url req
    case hmacRequestHook of
        Nothing   -> pure ()
        Just hook -> lift $ hook signedRequest
    pure signedRequest

instance RunClient HmacClientM where
    runRequest :: Servant.Request -> HmacClientM Servant.Response
    runRequest = hmacClientSign >=> hmacifyClient . runRequest

    streamingRequest :: Servant.Request -> HmacClientM Servant.StreamingResponse
    streamingRequest = hmacClientSign >=> hmacifyClient . streamingRequest

    throwServantError :: ServantError -> HmacClientM a
    throwServantError = hmacifyClient . throwServantError

runHmacClient
    :: HmacSettings
    -> ClientEnv
    -> HmacClientM a
    -> IO (Either ServantError a)
runHmacClient settings env client =
    runClientM (runReaderT (runHmacClientM client) settings) env

-- | Generates a set of client functions for an API.
hmacClient :: forall api . HasClient HmacClientM api => Client HmacClientM api
hmacClient = Proxy @api `clientIn` Proxy @HmacClientM

----------------------------------------------------------------------------
-- Internals
----------------------------------------------------------------------------

servantRequestToPayload :: BaseUrl -> Servant.Request -> RequestPayload
servantRequestToPayload url sreq = RequestPayload
    { rpMethod  = Client.method req
    , rpContent = toBsBody $ Client.requestBody req
    , rpHeaders = keepWhitelistedHeaders
                $ ("Host", host)
                : ("Accept-Encoding", "gzip")
                : Client.requestHeaders req

    , rpRawUrl  = host <> Client.path req <> Client.queryString req
    }
  where
    req :: Client.Request
    req = requestToClientRequest url sreq
        { Servant.requestQueryString =
             fromList $ sort $ toList $ Servant.requestQueryString sreq
        }

    host :: ByteString
    host = Client.host req

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
