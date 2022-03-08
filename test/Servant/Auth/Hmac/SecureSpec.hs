module Servant.Auth.Hmac.SecureSpec (spec) where

import Control.Exception (SomeException (SomeException))
import Control.Monad.IO.Class (MonadIO (liftIO))
import Control.Monad.Trans.Except (runExceptT)
import Data.Either (fromRight)
import Data.String (fromString)
import Network.HTTP.Client hiding (Proxy)
import Network.HTTP.Types (Status, unauthorized401)
import qualified Network.Wai.Handler.Warp as Warp
import Servant
import Servant.Auth.Hmac (SecretKey (..), signSHA256)
import Servant.Auth.Hmac.Secure
import Servant.Client
import Servant.Types.SourceT (StepT (Error), fromStepT, runSourceT, source)
import Test.Hspec

type TestApi = HelloEndpoint :<|> StreamingEndpoint
type UnsecuredApi = UnsecuredHelloEndpoint

type HelloEndpoint = HmacAuthed :> UnsecuredHelloEndpoint
type UnsecuredHelloEndpoint = "hello" :> Capture "name" String :> QueryFlag "bye" :> ReqBody '[PlainText] String :> Post '[PlainText] String

type StreamingEndpoint = HmacAuthed :> UnsecuredStreamingEndpoint
type UnsecuredStreamingEndpoint = "stream" :> StreamBody NewlineFraming PlainText (SourceIO String) :> Post '[PlainText] String

hello :: String -> Bool -> String -> Handler String
hello name bye = pure . (prefix <>) . reverse
  where
    prefix =
        if bye
            then "bye: "
            else "hello from " <> name <> ": "

stream :: SourceIO String -> Handler String
stream strsIO = do
    strs <- liftIO . runExceptT $ runSourceT strsIO
    pure . show . length . filter (not . null) $ fromRight [] strs

testApi :: Server TestApi
testApi = hello :<|> stream

unsecuredTestApi :: Server UnsecuredApi
unsecuredTestApi = hello

testApp :: SecretKey -> Application
testApp sk = serveWithContext (Proxy @TestApi) (hmacAuthCheckContext signSHA256 sk) testApi

unsecuredTestApp :: Application
unsecuredTestApp = serve (Proxy @UnsecuredApi) unsecuredTestApi

withTestApp :: SecretKey -> (Warp.Port -> IO ()) -> IO ()
withTestApp sk = Warp.testWithApplication (pure $ testApp sk)

withUnsecuredTestApp :: (Warp.Port -> IO ()) -> IO ()
withUnsecuredTestApp = Warp.testWithApplication (pure unsecuredTestApp)

apiLink :: (IsElem endpoint TestApi, HasLink endpoint) => Proxy endpoint -> MkLink endpoint Link
apiLink = safeLink (Proxy :: Proxy TestApi)

shouldBeASuccessWith :: (Show a, Eq a) => Either ClientError a -> a -> Expectation
errA `shouldBeASuccessWith` a = errA `shouldBe` Right a

shouldBeLink :: Link -> String -> Expectation
shouldBeLink link expected = toUrlPiece link `shouldBe` fromString expected

shouldBeAFailureWithStatus :: (Show a) => Either ClientError a -> Status -> Expectation
Left (FailureResponse _ resp) `shouldBeAFailureWithStatus` status = responseStatusCode resp `shouldBe` status
Left (DecodeFailure _ resp) `shouldBeAFailureWithStatus` status = responseStatusCode resp `shouldBe` status
Left (UnsupportedContentType _ resp) `shouldBeAFailureWithStatus` status = responseStatusCode resp `shouldBe` status
Left (InvalidContentTypeHeader resp) `shouldBeAFailureWithStatus` status = responseStatusCode resp `shouldBe` status
Left (ConnectionError e) `shouldBeAFailureWithStatus` status = expectationFailure $ "Expected '" <> show status <> "', got this instead: " <> show e
Right a `shouldBeAFailureWithStatus` status = expectationFailure $ "Expected '" <> show status <> "', got this instead: " <> show a

spec :: Spec
spec = do
    describe "Links" $ do
        it "should generate correct links ignoring the HMAC authentication requirement" $
            apiLink (Proxy @HelloEndpoint) "tom" True `shouldBeLink` "hello/tom?bye"

    describe "Client / Server" $ do
        let sk = SecretKey "abc123456"
        let anotherSk = SecretKey "something-else"

        baseUrl <- runIO $ parseBaseUrl "http://localhost"
        manager <- runIO $ newManager defaultManagerSettings
        let clientEnv port = mkClientEnv manager (baseUrl{baseUrlPort = port})

        context "With a secured server" $
            around (withTestApp sk) $ do
                let hmacAuthCheck = HmacAuthCheck signSHA256 sk
                let anotherHmacAuthCheck = HmacAuthCheck signSHA256 anotherSk

                let helloClient = hmacClient (Proxy @HelloEndpoint)
                let streamClient = hmacClient (Proxy @StreamingEndpoint)
                let unsecuredHelloClient = client (Proxy @UnsecuredHelloEndpoint)

                it "should have the server authenticate the client's secured request with the same secret" $ \port -> do
                    result <- runHmacClient (helloClient "world" False "abcdef123789") (clientEnv port) hmacAuthCheck
                    result `shouldBeASuccessWith` "hello from world: 987321fedcba"

                it "should have the server authenticate the client's secured streaming request with the same secret" $ \port -> do
                    result <- runHmacClient (streamClient (source ["abc", "", "123", "42", ""] :: SourceIO String)) (clientEnv port) hmacAuthCheck
                    result `shouldBeASuccessWith` "3"

                it "should have the server reject the client's secured request with a different secret and respond with a 401 status code" $ \port -> do
                    result <- runHmacClient (helloClient "you" True "jdkmsqjdl") (clientEnv port) anotherHmacAuthCheck
                    result `shouldBeAFailureWithStatus` unauthorized401

                it "should have the server reject the client's unsecured request and respond with a 401 status code" $ \port -> do
                    result <- runClientM (unsecuredHelloClient "me" False "00042") (clientEnv port)
                    result `shouldBeAFailureWithStatus` unauthorized401

                it "should have the HMAC signing failed before connection when the streaming request has failed during signing" $ \port -> do
                    result <- runHmacClient (streamClient (source ["hello", "", ""] <> fromStepT (Error "Failed!") :: SourceIO String)) (clientEnv port) hmacAuthCheck
                    result `shouldBe` Left (ConnectionError . SomeException $ RequestBodyHashingFailed "Failed!")

        context "With an unsecured server" $ do
            around withUnsecuredTestApp $ do
                let hmacAuthCheck = HmacAuthCheck signSHA256 sk
                let helloClient = hmacClient (Proxy @HelloEndpoint)

                it "should have the server respond to the client and ignore the client request's HMAC signature" $ \port -> do
                    result <- runHmacClient (helloClient "world" True "abcdef123789") (clientEnv port) hmacAuthCheck
                    result `shouldBeASuccessWith` "bye: 987321fedcba"
