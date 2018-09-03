{-# LANGUAGE AllowAmbiguousTypes #-}

-- | Signing functions.

module Servant.Auth.Hmac
       ( -- * Signing
         sign
       , signSHA256

         -- * Data types
       , SecretKey (..)
       , Signature (..)
       ) where

import Crypto.Hash.Algorithms (SHA256)
import Crypto.Hash.IO (HashAlgorithm)
import Crypto.MAC.HMAC (HMAC (hmacGetDigest), hmac)
import Data.ByteString (ByteString)

import qualified Data.ByteArray as BA (convert)


-- | The wraper for the secret key.
newtype SecretKey = SecretKey
    { unSecretKey :: ByteString
    }

-- | Hashed message used as the signature.
newtype Signature = Signature
    { unSignature :: ByteString
    }

-- | Compute the hashed message using the supplied hashing function.
sign :: forall a . (HashAlgorithm a)
     => SecretKey   -- ^ Secret key to use
     -> ByteString  -- ^ Message to MAC
     -> Signature  -- ^ Hashed message
sign (SecretKey sk) msg = Signature $ BA.convert $ hmacGetDigest $ hmac @_ @_ @a sk msg
{-# INLINE sign #-}

-- | 'sign' function specialized for 'SHA256' cryptographic algorithm.
signSHA256 :: SecretKey -> ByteString -> Signature
signSHA256 = sign @SHA256
{-# INLINE signSHA256 #-}
