{-# LANGUAGE AllowAmbiguousTypes #-}

{- |
Servant combinator and functions for HMAC authentication of requests.
-}
module Servant.Auth.Hmac.Secure (
    -- * Servant combinator
    HmacAuthed,

    -- * HMAC server
    HmacServerSideAuth (..),

    -- * HMAC client
    HmacClientSideAuth (..),
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
import Data.Kind (Type)
import Data.Sequence ((|>))
import qualified Data.Sequence as Seq
import Network.HTTP.Types.Header (HeaderName, hHost)
import qualified Network.Wai as Wai
import Servant (HasContextEntry (getContextEntry), HasLink (MkLink, toLink), HasServer (ServerT), Proxy (Proxy), ServerError (errBody), err401, type (:>))
import Servant.Auth.Hmac.Crypto (SecretKey, Signature (..), requestSignature, verifySignatureHmac)
import Servant.Auth.Hmac.Internal (normalizedHostFromUrl, servantDuplicateRequestBody, servantRequestToPayload, waiDuplicateRequestBody, waiRequestToPayload)
import Servant.Client (BaseUrl, ClientEnv (baseUrl), ClientError (ConnectionError), ClientM, HasClient (Client, hoistClientMonad), runClientM)
import Servant.Client.Core (RequestF (..), RunClient, clientIn)
import qualified Servant.Client.Core as Servant
import Servant.Client.Core.HasClient (HasClient (clientWithRoute))
import Servant.Client.Core.RunClient (RunClient (runRequestAcceptStatus, throwClientError))
import Servant.Server (HasServer (hoistServerWithContext, route))
import Servant.Server.Internal.Delayed (addAuthCheck)
import Servant.Server.Internal.DelayedIO (delayedFailFatal, withRequest)
import Servant.Server.Internal.RouteResult (RouteResult (FailFatal))
import Servant.Server.Internal.RoutingApplication (RoutingApplication)

-- | Potential error during the HMAC authentication generation or verification.
newtype HmacSignatureException
    = -- | The HMAC signature generation has failed during the request's body generation.
      RequestBodyInspectionFailed String
    deriving stock (Eq, Show)

instance Exception HmacSignatureException

{- Client-side HMAC authentication contextual information. -}
data HmacClientSideAuth usr = HmacClientSideAuth
    { hcsaSign :: !(SecretKey -> ByteString -> Signature)
    -- ^ Signing algorithm used for the authentication, taking in both the
    -- secret and the request payload. The usual algorithm is 'signSHA256'.
    , hcsaUserRequest :: !(usr -> Servant.Request -> IO Servant.Request)
    -- ^ Update the request to include the user (if necessary)
    , hcsaSecretKey :: !(usr -> SecretKey)
    -- ^ User secret key used for the authentication.
    }

{- Server-side HMAC authentication contextual information. -}
data HmacServerSideAuth usr = HmacServerSideAuth
    { hssaSign :: !(SecretKey -> ByteString -> Signature)
    -- ^ Signing algorithm used for the authentication, taking in both the
    -- secret and the request payload. The usual algorithm is 'signSHA256'.
    , hssaIdentifyUser :: !(Wai.Request -> IO (Maybe usr))
    -- ^ Identify the user from the incoming request. This is required to
    -- identify which secret key to use for authentication. The function only
    -- tries and identifies the user from the request. The authentication
    -- itself will be performed by the library using the secret key returned
    -- by 'hssaSecretKey'. May return 'Nothing' if the user could not be
    -- identified.
    , hssaSecretKey :: !(usr -> SecretKey)
    -- ^ Generate the secret key to use for the authentication.
    --  The secret key may change depending on the remote user.
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

'usr' is the type of user that may be authenticated through HMAC.
-}
data HmacAuthed (usr :: Type)

instance HasLink sub => HasLink (HmacAuthed usr :> sub) where
    type MkLink (HmacAuthed usr :> sub) r = MkLink sub r
    toLink toA _ = toLink toA (Proxy @sub)

newtype HmacClientM usr a = HmacClientM
    {unHmacClientM :: ReaderT (HmacClientSideAuth usr, usr) ClientM a}
    deriving (Functor, Applicative, Monad, MonadError ClientError, MonadIO, MonadReader (HmacClientSideAuth usr, usr))

instance RunClient (HmacClientM usr) where
    runRequestAcceptStatus st = signOnMark >=> liftClient . runRequestAcceptStatus st
    throwClientError = liftClient . throwClientError

liftClient :: ClientM a -> HmacClientM usr a
liftClient = HmacClientM . ReaderT . const

hmacClient :: forall api usr. HasClient (HmacClientM usr) api => Proxy api -> Client (HmacClientM usr) api
hmacClient _ = Proxy @api `clientIn` Proxy @(HmacClientM usr)

runHmacClient :: HmacClientM usr a -> ClientEnv -> HmacClientSideAuth usr -> usr -> IO (Either ClientError a)
runHmacClient ma env hac usr = runClientM (runReaderT (unHmacClientM ma) (hac, usr)) env

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
signOnMark :: Servant.Request -> HmacClientM usr Servant.Request
signOnMark req = do
    (HmacClientSideAuth signer userReq userSk, usr) <- ask
    url <- liftClient $ asks baseUrl
    completedReq <- completeRequest url <$> liftIO (userReq usr req)

    case findAuthenticationHeader (Servant.requestHeaders completedReq) of
        Nothing ->
            pure completedReq
        Just authHeaderIdx -> do
            let sk = userSk usr
            x <- servantDuplicateRequestBody completedReq
            case x of
                Left err -> throwError . ConnectionError . SomeException $ RequestBodyInspectionFailed err
                Right (req', body) -> do
                    let payload = servantRequestToPayload url body (completedReq{requestHeaders = Seq.deleteAt authHeaderIdx (requestHeaders completedReq)})
                    let signature = requestSignature signer sk payload
                    pure $ req'{requestHeaders = Seq.update authHeaderIdx (hAuthentication, hmacAuthenticationHeaderValue signature) (requestHeaders req')}
  where
    findAuthenticationHeader = Seq.elemIndexL (hAuthentication, hmacMarkValue)

instance (HasClient m api) => HasClient m (HmacAuthed usr :> api) where
    type Client m (HmacAuthed usr :> api) = Client m api

    clientWithRoute mp _ = clientWithRoute mp (Proxy @api) . markRequestForSignature
      where
        markRequestForSignature req = req{requestHeaders = requestHeaders req |> (hAuthentication, hmacMarkValue)}

    hoistClientMonad mp _ f cl = hoistClientMonad mp (Proxy @api) f cl

instance (HasServer api context, HasContextEntry context (HmacServerSideAuth usr)) => HasServer (HmacAuthed usr :> api) context where
    type ServerT (HmacAuthed usr :> api) m = usr -> ServerT api m

    route _ context subserver = verifyIfAuthed hmacSsAuth <$> route (Proxy @api) context (subserver `addAuthCheck` userIdentification)
      where
        hmacSsAuth = getContextEntry context

        userIdentification = withRequest $ \req -> do
            usr' <- liftIO (hssaIdentifyUser hmacSsAuth req)
            case usr' of
                Nothing -> delayedFailFatal err401
                Just usr -> pure usr

    hoistServerWithContext _ cp nt s = hoistServerWithContext (Proxy @api) cp nt . s

verifyIfAuthed :: HmacServerSideAuth usr -> RoutingApplication -> RoutingApplication
verifyIfAuthed (HmacServerSideAuth signer reqUser userSk) app req respond = do
    (req', body) <- waiDuplicateRequestBody req
    let payload = waiRequestToPayload req body
    usr' <- liftIO $ reqUser req'
    case usr' of
        Nothing ->
            respond $ FailFatal err401
        Just usr ->
            case verifySignatureHmac signer (userSk usr) payload of
                Nothing -> app req' respond
                Just bs -> respond $ FailFatal err401{errBody = bs}
