{-# LANGUAGE AllowAmbiguousTypes #-}

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
       , signRequest
       , verifyRequestHmac
       ) where

import Crypto.Hash (hash)
import Crypto.Hash.Algorithms (MD5, SHA256)
import Crypto.Hash.IO (HashAlgorithm)
import Crypto.MAC.HMAC (HMAC (hmacGetDigest), hmac)
import Data.Bifunctor (second)
import Data.ByteString (ByteString)
import Data.CaseInsensitive (foldedCase)
import Data.List (sort)
import Data.Maybe (fromMaybe)
import Network.HTTP.Types (Header, HeaderName)
import Network.Wai (Request, rawPathInfo, rawQueryString, requestBody, requestHeaderHost,
                    requestHeaders, requestMethod)

import qualified Data.ByteArray as BA (convert)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as Base64

----------------------------------------------------------------------------
-- Crypto
----------------------------------------------------------------------------

-- | The wraper for the secret key.
newtype SecretKey = SecretKey
    { unSecretKey :: ByteString
    }

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
signRequest
    :: (SecretKey -> ByteString -> Signature)  -- ^ Signing function
    -> SecretKey  -- ^ Secret key to use
    -> Request  -- ^ Request to sign
    -> IO Signature
signRequest signer sk = fmap (signer sk) . createStringToSign
  where
    createStringToSign :: Request -> IO ByteString
    createStringToSign req = getRequestBody req >>= \body -> pure $ BS.intercalate "\n"
        [ requestMethod req
        , hashMD5 body
        , normalizeHeaders $ requestHeaders req
        , fromMaybe mempty (requestHeaderHost req) <> rawPathInfo req <> rawQueryString req
        ]

    normalizeHeaders :: [Header] -> ByteString
    normalizeHeaders = BS.intercalate "\n" . sort . map normalize
      where
        normalize :: Header -> ByteString
        normalize (name, value) = foldedCase name <> value

verifyRequestHmac
    :: (SecretKey -> ByteString -> Signature)  -- ^ Signing function
    -> SecretKey
    -> Request
    -> IO Bool
verifyRequestHmac signer sk signedReq = case unsignedRequest of
    Nothing         -> pure False
    Just (req, sig) -> (sig ==) <$> signRequest signer sk req
  where
    -- Extracts HMAC signature from request and returns request with @authHeaderName@ header
    unsignedRequest :: Maybe (Request, Signature)
    unsignedRequest = case extractOn isAuthHeader $ requestHeaders signedReq of
        (Nothing, _) -> Nothing
        (Just (_, val), headers) -> BS.stripPrefix "HMAC " val >>= \sig -> Just
            ( signedReq { requestHeaders = headers }
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

getRequestBody :: Request -> IO ByteString
getRequestBody request = BS.concat <$> getChunks
  where
    getChunks :: IO [ByteString]
    getChunks = requestBody request >>= \chunk ->
        if chunk == BS.empty
        then pure []
        else (chunk:) <$> getChunks

-- | Removes and returns first element from list that satisfies given predicate.
extractOn :: forall a . (a -> Bool) -> [a] -> (Maybe a, [a])
extractOn p = go
  where
    go :: [a] -> (Maybe a, [a])
    go [] = (Nothing, [])
    go (x:xs)
        | p x       = (Just x, xs)
        | otherwise = second (x:) (go xs)
