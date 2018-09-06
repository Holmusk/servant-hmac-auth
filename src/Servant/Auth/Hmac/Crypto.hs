{-# LANGUAGE AllowAmbiguousTypes #-}

-- | Crypto primitives for hmac signing.

module Servant.Auth.Hmac.Crypto
       ( -- * Crypto primitives
         SecretKey (..)
       , Signature (..)
       , sign
       , signSHA256

         -- * Request signing
       , RequestPayload (..)
       , requestSignature
       , verifySignatureHmac

         -- * Internals
       , authHeaderName
       ) where

import Crypto.Hash (hash)
import Crypto.Hash.Algorithms (MD5, SHA256)
import Crypto.Hash.IO (HashAlgorithm)
import Crypto.MAC.HMAC (HMAC (hmacGetDigest), hmac)
import Data.ByteString (ByteString)
import Data.CaseInsensitive (foldedCase)
import Data.List (sort, uncons)
import Network.HTTP.Types (Header, HeaderName, Method, RequestHeaders)

import qualified Data.ByteArray as BA (convert)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as Base64

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
     -> Signature   -- ^ Hashed message
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
-- Request signing
----------------------------------------------------------------------------

-- | Part of the HTTP request that will be signed.
data RequestPayload = RequestPayload
    { rpMethod  :: !Method  -- ^ HTTP method
    , rpContent :: !ByteString  -- ^ Raw content of HTTP body
    , rpHeaders :: !RequestHeaders  -- ^ All headers of HTTP request
    , rpRawUrl  :: !ByteString  -- ^ Raw request URL with host, path pieces and parameters
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
