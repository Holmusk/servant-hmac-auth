{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE InstanceSigs #-}

-- | Servant client authentication.
module Servant.Auth.Hmac.Client (
    -- * HMAC client settings
    HmacSettings (..),
    defaultHmacSettings,

    -- * HMAC servant client
    HmacClientM (..),
    runHmacClient,
    hmacClient,
) where

import Control.Monad ((>=>))
import Control.Monad.IO.Class (MonadIO (..))
import Control.Monad.Reader (MonadReader (..), ReaderT, asks, runReaderT)
import Control.Monad.Trans.Class (lift)
import Data.ByteString (ByteString)
import Data.CaseInsensitive (mk)
import Data.Foldable (toList)
import Data.List (sort)
import Data.Proxy (Proxy (..))
import Data.Sequence (fromList, (<|))
import Data.String (fromString)
import qualified Network.HTTP.Client as Client
import Servant.Auth.Hmac.Crypto (
    RequestPayload (..),
    SecretKey,
    Signature (..),
    authHeaderName,
    keepWhitelistedHeaders,
    requestSignature,
    signSHA256,
 )
import Servant.Client (
    BaseUrl,
    Client,
    ClientEnv (baseUrl),
    ClientError,
    ClientM,
    HasClient,
    runClientM,
 )
import Servant.Client.Core (RunClient (..), clientIn)
import qualified Servant.Client.Core as Servant
import Servant.Client.Internal.HttpClient (defaultMakeClientRequest)

-- | Environment for 'HmacClientM'. Contains all required settings for hmac client.
data HmacSettings = HmacSettings
    { hmacSigner :: SecretKey -> ByteString -> Signature
    -- ^ Singing function that will sign all outgoing requests.
    , hmacSecretKey :: SecretKey
    -- ^ Secret key for signing function.
    , hmacRequestHook :: Maybe (Servant.Request -> ClientM ())
    -- ^ Function to call for every request after this request is signed.
    -- Useful for debugging.
    }

{- | Default 'HmacSettings' with the following configuration:

1. Signing function is 'signSHA256'.
2. Secret key is provided.
3. 'hmacRequestHook' is 'Nothing'.
-}
defaultHmacSettings :: SecretKey -> HmacSettings
defaultHmacSettings sk =
    HmacSettings
        { hmacSigner = signSHA256
        , hmacSecretKey = sk
        , hmacRequestHook = Nothing
        }

{- | @newtype@ wrapper over 'ClientM' that signs all outgoing requests
automatically.
-}
newtype HmacClientM a = HmacClientM
    { runHmacClientM :: ReaderT HmacSettings ClientM a
    }
    deriving (Functor, Applicative, Monad, MonadIO, MonadReader HmacSettings)

hmacifyClient :: ClientM a -> HmacClientM a
hmacifyClient = HmacClientM . lift

hmacClientSign :: Servant.Request -> HmacClientM Servant.Request
hmacClientSign req = HmacClientM $ do
    HmacSettings{..} <- ask
    url <- lift $ asks baseUrl
    let signedRequest = signRequestHmac hmacSigner hmacSecretKey url req
    case hmacRequestHook of
        Nothing -> pure ()
        Just hook -> lift $ hook signedRequest
    pure signedRequest

instance RunClient HmacClientM where
    runRequestAcceptStatus s = hmacClientSign >=> hmacifyClient . runRequestAcceptStatus s

    throwClientError :: ClientError -> HmacClientM a
    throwClientError = hmacifyClient . throwClientError

runHmacClient ::
    HmacSettings ->
    ClientEnv ->
    HmacClientM a ->
    IO (Either ClientError a)
runHmacClient settings env client =
    runClientM (runReaderT (runHmacClientM client) settings) env

-- | Generates a set of client functions for an API.
hmacClient :: forall api. HasClient HmacClientM api => Client HmacClientM api
hmacClient = Proxy @api `clientIn` Proxy @HmacClientM

----------------------------------------------------------------------------
-- Internals
----------------------------------------------------------------------------

servantRequestToPayload :: BaseUrl -> Servant.Request -> RequestPayload
servantRequestToPayload url sreq =
    RequestPayload
        { rpMethod = Client.method req
        , rpContent = "" -- Deprecation notice: this version doesn't use the request body for authentication. Use the new 'HmacAuthed' API for that.
        , rpHeaders =
            keepWhitelistedHeaders $
                -- FIXME we shouldn't add the 'Host' port ourselves. The client is responsible for that.
                ("Host", hostAndPort) :
                -- ("Accept-Encoding", "gzip") :
                Client.requestHeaders req
        , rpRawUrl = hostAndPort <> Client.path req <> Client.queryString req
        }
  where
    req :: Client.Request
    req =
        defaultMakeClientRequest
            url
            sreq
                { Servant.requestQueryString =
                    fromList $ sort $ toList $ Servant.requestQueryString sreq
                }

    hostAndPort :: ByteString
    hostAndPort = case lookup (mk "Host") (Client.requestHeaders req) of
        Just hp -> hp
        Nothing ->
            case (Client.secure req, Client.port req) of
                (True, 443) -> Client.host req
                (False, 80) -> Client.host req
                (_, p) -> Client.host req <> ":" <> fromString (show p)

{- | Adds signed header to the request.

@
Authentication: HMAC <signature>
@
-}
signRequestHmac ::
    -- | Signing function
    (SecretKey -> ByteString -> Signature) ->
    -- | Secret key that was used for signing 'Request'
    SecretKey ->
    -- | Base url for servant request
    BaseUrl ->
    -- | Original request
    Servant.Request ->
    -- | Signed request
    Servant.Request
signRequestHmac signer sk url req =
    let payload = servantRequestToPayload url req
        signature = requestSignature signer sk payload
        authHead = (authHeaderName, "HMAC " <> unSignature signature)
     in req{Servant.requestHeaders = authHead <| Servant.requestHeaders req}
