{-# LANGUAGE PolyKinds #-}

{- |
Servant combinator and functions for HMAC authentication of requests.
-}
module Servant.Auth.Hmac.Secure (
    -- * Servant combinator and context
    HmacAuthed,
    HmacAuthCheck (..),
    hmacAuthCheckContext,

    -- * HMAC client
    hmacClient,
    runHmacClient,

    -- * Miscellaneous
    HmacSignatureException (..),
) where

import Control.Exception (Exception, SomeException (SomeException))
import Control.Monad ((>=>))
import Control.Monad.Except (MonadError (throwError))
import Control.Monad.IO.Class (MonadIO (..))
import Control.Monad.Reader (MonadReader (ask), ReaderT (ReaderT, runReaderT), asks)
import Data.ByteString (ByteString)
import Data.Sequence ((|>))
import qualified Data.Sequence as Seq
import Network.HTTP.Types (HeaderName)
import Network.HTTP.Types.Header (hHost)
import Servant (Context (EmptyContext, (:.)), HasContextEntry (getContextEntry), HasLink (MkLink, toLink), HasServer (ServerT), Proxy (Proxy), ServerError (errBody), err401, type (:>))
import Servant.Auth.Hmac.Crypto (SecretKey, Signature (..), requestSignature, verifySignatureHmac)
import Servant.Auth.Hmac.Internal (normalizedHostFromUrl, servantDuplicateRequestBody, servantRequestToPayload, waiDuplicateRequestBody, waiRequestToPayload)
import Servant.Client (BaseUrl, ClientEnv (baseUrl), ClientError (ConnectionError), ClientM, HasClient (Client, hoistClientMonad), runClientM)
import Servant.Client.Core (RequestF (..), RunClient, clientIn)
import qualified Servant.Client.Core as Servant
import Servant.Client.Core.HasClient (HasClient (clientWithRoute))
import Servant.Client.Core.RunClient (RunClient (runRequestAcceptStatus, throwClientError))
import Servant.Server (HasServer (hoistServerWithContext, route))
import Servant.Server.Internal.RouteResult (RouteResult (FailFatal))
import Servant.Server.Internal.RoutingApplication (RoutingApplication)

-- | Potential error during the HMAC authentication generation or verification.
newtype HmacSignatureException
    = -- | The HMAC signature generation has failed during the request's body hashing.
      RequestBodyHashingFailed String
    deriving stock (Eq, Show)

instance Exception HmacSignatureException

{- HMAC authentication contextual information. -}
data HmacAuthCheck = HmacAuthCheck
    { -- | Signing algorithm used for the authentication, taking in both the
      -- secret and the request payload. The usual algorithm is 'signSHA256'.
      hacSign :: !(SecretKey -> ByteString -> Signature)
    , -- | Secret key used for the authentication.
      hacSecretKey :: !SecretKey
    }

{- | The HMAC authentication combinator.

Note that the HMAC signature check is done very early on server-side as opposed
to in the regular delayed workflow. Indeed, the request's content needs to be
inspected and reinjected and that can only happen before the request is handled
because of lazyness (i.e. inspecting the content will consume it and make it
lost to the server backend). Checking for the signature before checking for
captures and method seems acceptable.

IMPORTANT NOTE: the HMAC authentication scheme requires hashing the entirety of
the content. The later is still required though by the backend for consumption.
To that end, it will be retained in-memory. Users need to keep that in mind, and
take the necessary precautions to prevent any DoS attacks by throwing very large
payloads to the protected endpoint.
-}
data HmacAuthed

instance HasLink sub => HasLink (HmacAuthed :> sub) where
    type MkLink (HmacAuthed :> sub) r = MkLink sub r
    toLink toA _ = toLink toA (Proxy @sub)

newtype HmacClientM a = HmacClientM
    {unHmacClientM :: ReaderT HmacAuthCheck ClientM a}
    deriving (Functor, Applicative, Monad, MonadError ClientError, MonadIO, MonadReader HmacAuthCheck)

instance RunClient HmacClientM where
    runRequestAcceptStatus st = signOnMark >=> liftClient . runRequestAcceptStatus st
    throwClientError = liftClient . throwClientError

liftClient :: ClientM a -> HmacClientM a
liftClient = HmacClientM . ReaderT . const

hmacClient :: forall api. HasClient HmacClientM api => Proxy api -> Client HmacClientM api
hmacClient _ = Proxy @api `clientIn` Proxy @HmacClientM

runHmacClient :: HmacClientM a -> ClientEnv -> HmacAuthCheck -> IO (Either ClientError a)
runHmacClient ma env hac = runClientM (runReaderT (unHmacClientM ma) hac) env

hAuthentication :: HeaderName
hAuthentication = "Authentication"

hmacMarkValue :: ByteString
hmacMarkValue = "HMAC -"

hmacAuthenticationHeaderValue :: Signature -> ByteString
hmacAuthenticationHeaderValue (Signature sig) = "HMAC " <> sig

{- | Ensures that the request has all the required headers as expected server-side.
 The current implementation essentially ensures that the 'Host' header is set.
 All missing headers are appended to the current list of headers.
-}
completeRequest :: BaseUrl -> Servant.Request -> Servant.Request
completeRequest url req =
    case Seq.findIndexL ((== hHost) . fst) (requestHeaders req) of
        Just _ -> req
        Nothing ->
            req
                { requestHeaders =
                    requestHeaders req |> (hHost, normalizedHostFromUrl url)
                }

-- | HMAC-Sign the request if it has been marked for it.
signOnMark :: Servant.Request -> HmacClientM Servant.Request
signOnMark req = case findAuthenticationHeader (Servant.requestHeaders req) of
    Nothing ->
        pure req
    Just authHeaderIdx -> do
        url <- liftClient $ asks baseUrl
        HmacAuthCheck signer sk <- ask
        let completedReq = completeRequest url req
        x <- servantDuplicateRequestBody completedReq
        case x of
            Left err -> throwError . ConnectionError . SomeException $ RequestBodyHashingFailed err
            Right (req', body) -> do
                let payload = servantRequestToPayload url body (completedReq{requestHeaders = Seq.deleteAt authHeaderIdx (requestHeaders completedReq)})
                let signature = requestSignature signer sk payload
                pure $ req'{requestHeaders = Seq.update authHeaderIdx (hAuthentication, hmacAuthenticationHeaderValue signature) (requestHeaders req')}
  where
    findAuthenticationHeader = Seq.elemIndexL (hAuthentication, hmacMarkValue)

instance (HasClient m api) => HasClient m (HmacAuthed :> api) where
    type Client m (HmacAuthed :> api) = Client m api

    clientWithRoute mp _ = clientWithRoute mp (Proxy @api) . markRequestForSignature
      where
        markRequestForSignature req = req{requestHeaders = requestHeaders req |> (hAuthentication, hmacMarkValue)}

    hoistClientMonad mp _ f cl = hoistClientMonad mp (Proxy @api) f cl

instance (HasServer api context, HasContextEntry context HmacAuthCheck) => HasServer (HmacAuthed :> api) context where
    type ServerT (HmacAuthed :> api) m = ServerT api m

    route _ context = fmap (verifyIfAuthed hmacAuthCheck) . route (Proxy @api) context
      where
        hmacAuthCheck = getContextEntry context

    hoistServerWithContext _ cp nt s = hoistServerWithContext (Proxy @api) cp nt s

verifyIfAuthed :: HmacAuthCheck -> RoutingApplication -> RoutingApplication
verifyIfAuthed (HmacAuthCheck hmacSigner hmacSk) app req respond = do
    (req', body) <- waiDuplicateRequestBody req
    let payload = waiRequestToPayload req body
    let verification = verifySignatureHmac hmacSigner hmacSk payload
    case verification of
        Nothing -> app req' respond
        Just bs -> respond $ FailFatal err401{errBody = bs}

-- | Create a HMAC request for HMAC authentication.
hmacAuthCheckContext ::
    -- | Signing function
    (SecretKey -> ByteString -> Signature) ->
    -- | Secret key that was used for signing 'Request'
    SecretKey ->
    Context '[HmacAuthCheck]
hmacAuthCheckContext signer sk = HmacAuthCheck signer sk :. EmptyContext
