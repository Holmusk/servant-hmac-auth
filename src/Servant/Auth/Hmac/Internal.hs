{-# OPTIONS_GHC -Wno-deprecations #-}

-- Remove WAI's 'requestBody' deprecation warning as its usage is intentional
-- and not subject to the actual warning.
module Servant.Auth.Hmac.Internal (
    -- * Payload handling
    servantRequestToPayload,
    waiRequestToPayload,

    -- * Request handling
    servantDuplicateRequestBody,
    waiDuplicateRequestBody,
    normalizedHostFromUrl,
) where

import Control.Concurrent (modifyMVar, newMVar)
import Control.Monad.Except (runExceptT)
import Control.Monad.IO.Class (MonadIO (liftIO))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Data.CaseInsensitive (mk)
import Data.Foldable (toList)
import Data.Functor ((<&>))
import Data.List (sort)
import Data.Maybe (fromMaybe)
import Data.Sequence (Seq, fromList)
import Data.String (fromString)
import qualified Network.HTTP.Client as Client
import qualified Network.HTTP.Types as Client
import qualified Network.Wai as Wai
import Servant.Auth.Hmac.Crypto (RequestPayload (RequestPayload, rpContent, rpHeaders, rpMethod, rpRawUrl), keepWhitelistedHeaders)
import Servant.Client (BaseUrl (BaseUrl), Scheme (Http, Https), defaultMakeClientRequest)
import qualified Servant.Client.Core as Servant
import Servant.Types.SourceT (runSourceT, source)

{- | Generate a 'RequestPayload' from a Servant 'Request' with a 'BaseUrl' and
 explicit body content. The actual content from the Servant request will not be
 used as it would be lost on first consumption.
-}
servantRequestToPayload :: BaseUrl -> ByteString -> Servant.Request -> RequestPayload
servantRequestToPayload url body sreq = do
    RequestPayload
        { rpMethod = Client.method req
        , rpContent = body
        , rpHeaders =
            keepWhitelistedHeaders $
                {- FIXME: Removed from the previous version. These should be
                   handled by the client. We shouldn't change an explicitly set
                   'Host', nor should we say the client accept a specific
                   encoding if it doesn't. Any particular reason we have these
                   here? Because these are actually used for the signature, it
                   shoudl be the responsibility of the caller to have them set
                   before generating the signature... -}
                -- ("Host", hostAndPort) :
                -- ("Accept-Encoding", "gzip") :
                Client.requestHeaders req
        , rpRawUrl = hostAndPort <> Client.path req <> Client.queryString req
        }
  where
    req :: Client.Request
    req = defaultMakeClientRequest url sreq{Servant.requestQueryString = normalizedQueryString}

    normalizedQueryString :: Seq Client.QueryItem
    normalizedQueryString = fromList . sort . toList $ Servant.requestQueryString sreq

    hostAndPort :: ByteString
    hostAndPort = case lookup (mk "Host") (Client.requestHeaders req) of
        Just hp -> hp
        Nothing -> normalizedHostFromUrl url

{- | Generate a 'RequestPayload'  from a WAI 'Request' with an explicit body
 content. The actual content from the request will not be used as it would be
 lost on first consumption.
-}
waiRequestToPayload :: Wai.Request -> ByteString -> RequestPayload
waiRequestToPayload req content = do
    RequestPayload
        { rpMethod = Wai.requestMethod req
        , rpContent = content
        , rpHeaders = keepWhitelistedHeaders $ Wai.requestHeaders req
        , rpRawUrl = fromMaybe mempty (Wai.requestHeaderHost req) <> Wai.rawPathInfo req <> Wai.rawQueryString req
        }

{- | Generate the normalized host name and port from the given URL. In the
 normalized version of those, the port is only specified if it is not the
 standard one for the current scheme.
-}
normalizedHostFromUrl :: BaseUrl -> ByteString
normalizedHostFromUrl (BaseUrl Http host 80 _) = fromString host
normalizedHostFromUrl (BaseUrl Https host 443 _) = fromString host
normalizedHostFromUrl (BaseUrl _ host port _) = fromString host <> ":" <> fromString (show port)

{- | Extract the body of the given request and return both a copy of it and a
 copy of the request with a copy of the body as well. This is necessary as the
 consumption of a request body is lazy and definitive.

 The returned copy of the body is entirely concatenated for simplicity. The
 different chunks inside the request are preserved though.

 NOTE: The extracted body is a strict 'ByteString'. As such, very large request
 body will be entirely stored in-memory.
-}
servantDuplicateRequestBody :: MonadIO m => Servant.Request -> m (Either String (Servant.Request, ByteString))
servantDuplicateRequestBody req@Servant.Request{Servant.requestBody = Nothing} = pure $ Right (req, BS.empty)
servantDuplicateRequestBody req@Servant.Request{Servant.requestBody = Just body} =
    case body of
        (Servant.RequestBodyLBS lbs, _) ->
            pure $ Right (req, BSL.toStrict lbs)
        (Servant.RequestBodyBS bs, _) ->
            pure $ Right (req, bs)
        (Servant.RequestBodySource src, mimeType) -> do
            liftIO (runExceptT $ runSourceT src) <&> \case
                Left err ->
                    Left err
                Right chunks ->
                    Right
                        ( req{Servant.requestBody = Just (Servant.RequestBodySource $ source chunks, mimeType)}
                        , BSL.toStrict $ BSL.concat chunks
                        )

-- | WAI version of the 'servantDuplicateRequestBody' function.
waiDuplicateRequestBody :: MonadIO m => Wai.Request -> m (Wai.Request, ByteString)
waiDuplicateRequestBody req = do
    chunks <- liftIO . toListWhileM (/= BS.empty) $ Wai.getRequestBodyChunk req
    readNextChunk <- liftIO $ nextChunkReader chunks
    pure (req{Wai.requestBody = readNextChunk}, BS.concat chunks)
  where
    nextChunkReader chunks =
        let doRead mv = modifyMVar mv $ \case
                [] -> pure ([], BS.empty)
                h : t -> pure (t, h)
         in doRead <$> newMVar chunks

toListWhileM :: MonadIO m => (a -> Bool) -> m a -> m [a]
toListWhileM f = go []
  where
    go acc ma =
        ma >>= \a ->
            if f a
                then go (a : acc) ma
                else pure (reverse acc)
