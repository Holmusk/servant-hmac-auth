module Servant.Auth.HmacSpec (spec) where

import Data.Text (Text)
import qualified Data.Text as Text
import Network.HTTP.Client (defaultManagerSettings, newManager)
import Network.HTTP.Types (Status, unauthorized401)
import qualified Network.Wai.Handler.Warp as Warp
import Servant (
    Application,
    Handler,
    MimeRender,
    MimeUnrender,
    PlainText,
    Post,
    Proxy (Proxy),
    ReqBody,
    Server,
    serve,
    serveWithContext,
    type (:>),
 )
import Servant.Auth.Hmac (
    HmacAuth,
    SecretKey (SecretKey),
    defaultHmacSettings,
    hmacAuthServerContext,
    hmacClient,
    runHmacClient,
    signSHA256,
 )
import Servant.Client (
    BaseUrl (baseUrlPort),
    ClientError (..),
    ResponseF (responseStatusCode),
    client,
    mkClientEnv,
    parseBaseUrl,
    runClientM,
 )
import Test.Hspec (
    Expectation,
    Spec,
    around,
    context,
    describe,
    expectationFailure,
    it,
    runIO,
    shouldBe,
 )

newtype EchoMessage = EchoMessage
    {emContent :: Text}
    deriving stock (Eq, Show)
    deriving (MimeRender PlainText, MimeUnrender PlainText) via Text

type EchoApi =
    HmacAuth :> UnprotectedEchoApi

type UnprotectedEchoApi =
    -- Echo back a reversed message.
    "echo" :> ReqBody '[PlainText] EchoMessage :> Post '[PlainText] EchoMessage

echoBack :: EchoMessage -> Handler EchoMessage
echoBack (EchoMessage msg) = pure $ EchoMessage (Text.reverse msg)

unsecuredEchoServer :: Server UnprotectedEchoApi
unsecuredEchoServer = echoBack

unsecuredEchoApp :: Application
unsecuredEchoApp = serve (Proxy @UnprotectedEchoApi) unsecuredEchoServer

withUnsecuredEchoApp :: (Warp.Port -> IO ()) -> IO ()
withUnsecuredEchoApp = Warp.testWithApplication (pure unsecuredEchoApp)

securedEchoServer :: Server EchoApi
securedEchoServer = const echoBack

securedEchoApp :: SecretKey -> Application
securedEchoApp sk = serveWithContext (Proxy @EchoApi) (hmacAuthServerContext signSHA256 sk) securedEchoServer

withSecuredEchoApp :: SecretKey -> (Warp.Port -> IO ()) -> IO ()
withSecuredEchoApp sk = Warp.testWithApplication (pure $ securedEchoApp sk)

shouldBeASuccessWith :: (Show a, Eq a) => Either ClientError a -> a -> Expectation
errA `shouldBeASuccessWith` a = errA `shouldBe` Right a

shouldBeAFailureWithStatus :: (Show a) => Either ClientError a -> Status -> Expectation
Left (FailureResponse _ resp) `shouldBeAFailureWithStatus` status = responseStatusCode resp `shouldBe` status
Left (DecodeFailure _ resp) `shouldBeAFailureWithStatus` status = responseStatusCode resp `shouldBe` status
Left (UnsupportedContentType _ resp) `shouldBeAFailureWithStatus` status = responseStatusCode resp `shouldBe` status
Left (InvalidContentTypeHeader resp) `shouldBeAFailureWithStatus` status = responseStatusCode resp `shouldBe` status
Left (ConnectionError e) `shouldBeAFailureWithStatus` status = expectationFailure $ "Expected '" <> show status <> "', got this instead: " <> show e
Right a `shouldBeAFailureWithStatus` status = expectationFailure $ "Expected '" <> show status <> "', got this instead: " <> show a

spec :: Spec
spec =
    describe "Hmac" $ do
        let sk = SecretKey "not-so-secret-secret-key!"
        let anotherSk = SecretKey "some-other-key!!"

        context "with a secured server" $ do
            around (withSecuredEchoApp sk) $ do
                let securedEchoBack = hmacClient @UnprotectedEchoApi
                let unsecuredEchoBack = client (Proxy @UnprotectedEchoApi)

                baseUrl <- runIO $ parseBaseUrl "http://localhost"
                manager <- runIO $ newManager defaultManagerSettings
                let clientEnv port = mkClientEnv manager (baseUrl{baseUrlPort = port})

                it "should have the server authenticate the client's secured request with the same secret" $ \port -> do
                    result <- runHmacClient (defaultHmacSettings sk) (clientEnv port) (securedEchoBack $ EchoMessage "abcdef123789")
                    result `shouldBeASuccessWith` EchoMessage "987321fedcba"

                it "should have the server reject the client's secured request with a different secret and respond with a 401 status code" $ \port -> do
                    result <- runHmacClient (defaultHmacSettings anotherSk) (clientEnv port) (securedEchoBack $ EchoMessage "very sensitive message")
                    result `shouldBeAFailureWithStatus` unauthorized401

                it "should have the server reject the client's insecured request and respond with a 401 status code" $ \port -> do
                    result <- runClientM (unsecuredEchoBack $ EchoMessage "very sensitive message") (clientEnv port)
                    result `shouldBeAFailureWithStatus` unauthorized401

        context "with an unsecured server" $ do
            around withUnsecuredEchoApp $ do
                let securedEchoBack = hmacClient @UnprotectedEchoApi

                baseUrl <- runIO $ parseBaseUrl "http://localhost"
                manager <- runIO $ newManager defaultManagerSettings
                let clientEnv port = mkClientEnv manager (baseUrl{baseUrlPort = port})

                it "should have the server respond to the client and ignore the client request's HMAC signature" $ \port -> do
                    result <- runHmacClient (defaultHmacSettings sk) (clientEnv port) (securedEchoBack $ EchoMessage "abcdef123789")
                    result `shouldBeASuccessWith` EchoMessage "987321fedcba"
