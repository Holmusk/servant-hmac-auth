{-# LANGUAGE AllowAmbiguousTypes #-}

-- | Signing functions.

module Servant.Auth.Hmac
       ( -- * Signing
         sign
       , signSHA256

         -- * Secret key
       , SecretKey (..)
       ) where

import Crypto.Hash.Algorithms (SHA256)
import Crypto.Hash.IO (HashAlgorithm)
import Crypto.MAC.HMAC (HMAC (hmacGetDigest), hmac)
import Data.ByteString (ByteString, pack)

import qualified Data.ByteArray as BA (unpack)


-- | The wraper for the secret key.
newtype SecretKey = SecretKey
    { unSecretKey :: ByteString
    }

-- | Compute the hashed message using the supplied hashing function.
sign :: forall a . (HashAlgorithm a)
     => SecretKey   -- ^ Secret key to use
     -> ByteString  -- ^ Message to MAC
     -> ByteString  -- ^ Hashed message
sign (SecretKey sk) msg = pack $ BA.unpack $ hmacGetDigest $ hmac @_ @_ @a sk msg
{-# INLINE sign #-}

-- | 'sign' function specialized for 'SHA256' cryptographic algorithm.
signSHA256 :: SecretKey -> ByteString -> ByteString
signSHA256 = sign @SHA256
{-# INLINE signSHA256 #-}
