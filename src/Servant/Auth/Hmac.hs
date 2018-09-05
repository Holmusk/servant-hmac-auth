{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE TypeFamilies        #-}

-- | Signing functions.

module Servant.Auth.Hmac
       ( -- * Data types
         SecretKey (..)
       , Signature (..)

         -- * Signing
         -- ** Raw signing
       , sign
       , signSHA256

         -- ** Request signing
       , RequestPayload (..)
       , waiRequestToPayload
       , requestSignature
       , signRequestHmac
       , verifySignatureHmac

         -- * Servant
         -- ** server
       , HmacAuth
       , AuthContextHandlers
       , AuthContext
       , authServerContext
       , hmacAuthHandler

         -- ** client
       , HmacClient (..)
       ) where

import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ReaderT)
import Crypto.Hash (hash)
import Crypto.Hash.Algorithms (MD5, SHA256)
import Crypto.Hash.IO (HashAlgorithm)
import Crypto.MAC.HMAC (HMAC (hmacGetDigest), hmac)
import Data.ByteString (ByteString)
import Data.CaseInsensitive (foldedCase)
import Data.List (sort, uncons)
import Data.Maybe (fromMaybe)
import Data.String (IsString)
import Network.HTTP.Types (Header, HeaderName, Method, RequestHeaders)
import Network.Wai (Request, rawPathInfo, rawQueryString, requestBody, requestHeaderHost,
                    requestHeaders, requestMethod)
import Servant (Context ((:.), EmptyContext))
import Servant.API (AuthProtect)
import Servant.Client (ClientM)
import Servant.Server (Handler, err401, errBody)
import Servant.Server.Experimental.Auth (AuthHandler, AuthServerData, mkAuthHandler)

import qualified Data.ByteArray as BA (convert)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as Base64
import qualified Network.Wai as Wai (Request)

----------------------------------------------------------------------------
-- Crypto
----------------------------------------------------------------------------

-- | The wraper for the secret key.
newtype SecretKey = SecretKey
    { unSecretKey :: ByteString
    } deriving (IsString)

-- | Hashed message used as the signature. Encoded in Base64.
newtype Signature = Signature
    { unSignature :: ByteString
    } deriving (Eq)

{- | Compute the hashed message using the supplied hashing function. And then
encode the result in the Base64 encoding.
-}
sign :: forall algo . (HashAlgorithm algo)
     => SecretKey   -- ^ Secret key to use
     -> ByteString  -- ^ Message to MAC
     -> Signature  -- ^ Hashed message
sign (SecretKey sk) msg = Signature
                        $ Base64.encode
                        $ BA.convert
                        $ hmacGetDigest
                        $ hmac @_ @_ @algo sk msg
{-# INLINE sign #-}

-- | 'sign' function specialized for 'SHA256' cryptographic algorithm.
signSHA256 :: SecretKey -> ByteString -> Signature
signSHA256 = sign @SHA256
{-# INLINE signSHA256 #-}

----------------------------------------------------------------------------
-- Web
----------------------------------------------------------------------------

-- | Part of the HTTP request that will be signed.
data RequestPayload = RequestPayload
    { rpMethod  :: !Method  -- ^ HTTP method
    , rpContent :: !ByteString  -- ^ Raw content of HTTP body
    , rpHeaders :: !RequestHeaders  -- ^ All headers of HTTP request
    , rpRawUrl  :: !ByteString  -- ^ Raw request URL with host, path pieces and parameters
    }

waiRequestToPayload :: Wai.Request -> IO RequestPayload
waiRequestToPayload req = getWaiRequestBody req >>= \body -> pure RequestPayload
    { rpMethod  = requestMethod req
    , rpContent = body
    , rpHeaders = requestHeaders req
    , rpRawUrl  = fromMaybe mempty (requestHeaderHost req) <> rawPathInfo req <> rawQueryString req
    }

-- TODO: require Content-Type header?
-- TODO: require Date header with timestamp?
{- | This function signs HTTP request according to the following algorithm:

@
stringToSign = HTTP-Method       ++ "\n"
            ++ Content-MD5       ++ "\n"
            ++ HeadersNormalized ++ "\n"
            ++ RawURL

signature = encodeBase64
          $ signHmac yourSecretKey
          $ encodeUtf8 stringToSign
@

where @HeadersNormalized@ are headers decapitalzed, joined, sorted
alphabetically and intercalated with line break. So, if you have headers like
these:

@
User-Agent: Mozilla/5.0
Host: foo.bar.com
@

the result of header normalization will look like this:

@
hostfoo.bar.com
user-agentMozilla/5.0
@
-}
requestSignature
    :: (SecretKey -> ByteString -> Signature)  -- ^ Signing function
    -> SecretKey  -- ^ Secret key to use
    -> RequestPayload  -- ^ Payload to sign
    -> Signature
requestSignature signer sk = signer sk . createStringToSign
  where
    createStringToSign :: RequestPayload -> ByteString
    createStringToSign RequestPayload{..} = BS.intercalate "\n"
        [ rpMethod
        , hashMD5 rpContent
        , normalizeHeaders rpHeaders
        , rpRawUrl
        ]

    normalizeHeaders :: [Header] -> ByteString
    normalizeHeaders = BS.intercalate "\n" . sort . map normalize
      where
        normalize :: Header -> ByteString
        normalize (name, value) = foldedCase name <> value

{- | Adds signed header to the request.

@
Authentication: HMAC <signature>
@
-}
signRequestHmac
    :: (SecretKey -> ByteString -> Signature)  -- ^ Signing function
    -> SecretKey  -- ^ Secret key that was used for signing 'Request'
    -> Wai.Request  -- ^ Original request
    -> IO Wai.Request  -- ^ Signed request
signRequestHmac signer sk req = do
    payload <- waiRequestToPayload req
    let signature = requestSignature signer sk payload
    let authHead = (authHeaderName, "HMAC " <> unSignature signature)
    pure req
        { requestHeaders = authHead : requestHeaders req
        }

{- | This function takes signing function @signer@ and secret key and expects
that given 'Request' has header:

@
Authentication: HMAC <signature>
@

It checks whether @<signature>@ is true request signature.
-}
verifySignatureHmac
    :: (SecretKey -> ByteString -> Signature)  -- ^ Signing function
    -> SecretKey  -- ^ Secret key that was used for signing 'Request'
    -> RequestPayload
    -> Bool
verifySignatureHmac signer sk signedPayload = case unsignedPayload of
    Nothing         -> False
    Just (pay, sig) -> sig == requestSignature signer sk pay
  where
    -- Extracts HMAC signature from request and returns request with @authHeaderName@ header
    unsignedPayload :: Maybe (RequestPayload, Signature)
    unsignedPayload = case extractOn isAuthHeader $ rpHeaders signedPayload of
        (Nothing, _) -> Nothing
        (Just (_, val), headers) -> BS.stripPrefix "HMAC " val >>= \sig -> Just
            ( signedPayload { rpHeaders = headers }
            , Signature sig
            )

----------------------------------------------------------------------------
-- Internals
----------------------------------------------------------------------------

authHeaderName :: HeaderName
authHeaderName = "Authentication"

isAuthHeader :: Header -> Bool
isAuthHeader = (== authHeaderName) . fst

hashMD5 :: ByteString -> ByteString
hashMD5 = BA.convert . hash @_ @MD5

getWaiRequestBody :: Wai.Request -> IO ByteString
getWaiRequestBody request = BS.concat <$> getChunks
  where
    getChunks :: IO [ByteString]
    getChunks = requestBody request >>= \chunk ->
        if chunk == BS.empty
        then pure []
        else (chunk:) <$> getChunks

{- | Removes and returns first element from list that satisfies given predicate.

>>> extractOn (== 3) [1..5]
(Just 3, [1,2,4,5])
>>> extractOn (== 3) [5..10]
(Nothing,[5,6,7,8,9,10])
-}
extractOn :: (a -> Bool) -> [a] -> (Maybe a, [a])
extractOn p l =
    let (before, after) = break p l
    in case uncons after of
        Nothing      -> (Nothing, l)
        Just (x, xs) -> (Just x, before ++ xs)

----------------------------------------------------------------------------
-- Servant Server
----------------------------------------------------------------------------

type HmacAuth = AuthProtect "hmac-auth"

type instance AuthServerData HmacAuth = ()

type AuthContextHandlers = '[AuthHandler Request ()]
type AuthContext = Context AuthContextHandlers

authServerContext
    :: (SecretKey -> ByteString -> Signature)  -- ^ Signing function
    -> SecretKey  -- ^ Secret key that was used for signing 'Request'
    -> AuthContext
authServerContext signer sk = hmacAuthHandler signer sk :. EmptyContext

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
-- Servant client
----------------------------------------------------------------------------

-- | Environment for 'HmacClientM'.
data HmacSettings = HmacSettings
    { hmacSigner    :: SecretKey -> ByteString -> Signature
    , hmacSecretKey :: SecretKey
    }

{- | @newtype@ wrapper over 'ClientM' that signs all outgoing requests
automatically.
-}
newtype HmacClient a = HmacClient
    { runHmacClient :: ReaderT HmacSettings ClientM a
    } deriving (Functor, Applicative, Monad)
