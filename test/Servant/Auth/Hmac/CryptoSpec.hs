{-# LANGUAGE TemplateHaskellQuotes #-}

module Servant.Auth.Hmac.CryptoSpec (spec) where

import Data.CaseInsensitive
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import Network.HTTP.Types
import Servant.Auth.Hmac.Crypto (RequestPayload (..), SecretKey (..), Signature (..), requestSignature, signSHA256)
import System.FilePath
import Test.Hspec
import Test.Hspec.Golden

goldenTest :: String -> Text -> Golden Text
goldenTest name actualOutput =
    Golden
        { output = actualOutput
        , encodePretty = Text.unpack
        , writeToFile = TIO.writeFile
        , readFromFile = TIO.readFile
        , goldenFile = ".golden" </> name </> "golden"
        , actualFile = Just (".golden" </> name </> "actual")
        , failFirstTime = False
        }

sha256Scenarios :: [(SecretKey, RequestPayload)]
sha256Scenarios =
    [ (SecretKey "Some-s3cr3t", RequestPayload methodGet "" [(mk "Host", "my-server.local")] "http://my-server.local/test")
    , (SecretKey "s3cret2!", RequestPayload methodPost "This is a text content." [(mk "Host", "www.haskell.server"), (mk "User-Agent", "Mozilla/5.0"), (mk "Authentication", "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")] "https://www.haskell.server/test")
    , (SecretKey "123456789abcdef", RequestPayload methodPatch "\00HellowORLD" [(mk "Host", "files.myrepository.org"), (mk "Content-Encoding", "custom-fake-encoding"), (mk "Accept-Encoding", "gzip")] "https://files.myrepository.org/files/4601237722")
    ]

formatResponse :: [Signature] -> Text
formatResponse = Text.unlines . fmap (TE.decodeLatin1 . unSignature)

spec :: Spec
spec =
    describe "requestSignature" $
        context "when using SHA256 for signature" $
            it "should compute the request's signature" $
                let signatures = uncurry (requestSignature signSHA256) <$> sha256Scenarios
                    actualOutput = formatResponse signatures
                 in goldenTest (show 'requestSignature) actualOutput
