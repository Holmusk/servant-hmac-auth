module Servant.Auth.Hmac.SecureSpec (spec) where

import Control.Exception (SomeException (SomeException))
import Control.Monad.IO.Class (MonadIO (liftIO))
import Control.Monad.Trans.Except (runExceptT)
import Data.Either (fromRight)
import Data.List (intercalate)
import Data.String (fromString)
import Network.HTTP.Client hiding (Proxy)
import Network.HTTP.Types (Status, unauthorized401)
import qualified Network.Wai as Wai
import qualified Network.Wai.Handler.Warp as Warp
import Servant
import Servant.Auth.Hmac (SecretKey (..), signSHA256)
import Servant.Auth.Hmac.Secure
import Servant.Client
import qualified Servant.Client.Core as Client
import Servant.Types.SourceT (StepT (Error), fromStepT, runSourceT, source)
import Test.Hspec

type TestApi = HelloEndpoint :<|> StreamingEndpoint
type UnsecuredApi = UnsecuredHelloEndpoint

data HelloUser
    = UserA
    | UserB
    deriving stock (Show)

type HelloEndpoint = HmacAuthed HelloUser :> UnsecuredHelloEndpoint
type UnsecuredHelloEndpoint = "hello" :> Capture "name" String :> QueryFlag "bye" :> ReqBody '[PlainText] String :> Post '[PlainText] String

type StreamingEndpoint = HmacAuthed () :> UnsecuredStreamingEndpoint
type UnsecuredStreamingEndpoint = "stream" :> StreamBody NewlineFraming PlainText (SourceIO String) :> Post '[PlainText] String

helloImpl :: Maybe HelloUser -> String -> Bool -> String -> Handler String
helloImpl usr name bye = pure . (prefix <>) . reverse
  where
    prefix =
        if bye
            then "bye from " <> show usr <> ": "
            else "hello from " <> show usr <> " to " <> name <> ": "

hello :: HelloUser -> String -> Bool -> String -> Handler String
hello usr = helloImpl (Just usr)

stream :: () -> SourceIO String -> Handler String
stream _ strsIO = do
    strs <- liftIO . runExceptT $ runSourceT strsIO
    pure . intercalate "," . filter (not . null) $ fromRight [] strs

testApi :: Server TestApi
testApi = hello :<|> stream

unsecuredTestApi :: Server UnsecuredApi
unsecuredTestApi = helloImpl Nothing

testApp :: HmacServerSideAuth HelloUser -> HmacServerSideAuth () -> Application
testApp helloUserCtx unitUserCtx = serveWithContext (Proxy @TestApi) (helloUserCtx :. unitUserCtx :. EmptyContext) testApi

unsecuredTestApp :: Application
unsecuredTestApp = serve (Proxy @UnsecuredApi) unsecuredTestApi

withTestApp :: HmacServerSideAuth HelloUser -> HmacServerSideAuth () -> (Warp.Port -> IO ()) -> IO ()
withTestApp helloUserCtx unitUserCtx = Warp.testWithApplication (pure $ testApp helloUserCtx unitUserCtx)

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
        baseUrl <- runIO $ parseBaseUrl "http://localhost"
        manager <- runIO $ newManager defaultManagerSettings
        let clientEnv port = mkClientEnv manager (baseUrl{baseUrlPort = port})

        let userASk = SecretKey "abc123456"
        let userBSk = SecretKey "something-else"
        let unitSk = SecretKey "42"
        let fooUserHeader = "foo-user"
        let helloCtx =
                HmacServerSideAuth
                    { hssaSign = signSHA256
                    , hssaIdentifyUser = \req -> case lookup fooUserHeader (Wai.requestHeaders req) of
                        Just "user-a" -> pure $ Just UserA
                        Just "user-b" -> pure $ Just UserB
                        _ -> pure Nothing
                    , hssaSecretKey = \case
                        UserA -> userASk
                        UserB -> userBSk
                    }
        let unitCtx =
                HmacServerSideAuth
                    { hssaSign = signSHA256
                    , hssaIdentifyUser = const . pure $ Just ()
                    , hssaSecretKey = const unitSk
                    }
        let hmacHelloClientAuth =
                HmacClientSideAuth
                    { hcsaSign = signSHA256
                    , hcsaUserRequest = \case
                        UserA -> pure . Client.addHeader fooUserHeader ("user-a" :: String)
                        UserB -> pure . Client.addHeader fooUserHeader ("user-b" :: String)
                    , hcsaSecretKey = \case
                        UserA -> userASk
                        UserB -> userBSk
                    }
        let hmacUnitClientAuth =
                HmacClientSideAuth
                    { hcsaSign = signSHA256
                    , hcsaUserRequest = const pure
                    , hcsaSecretKey = const unitSk
                    }

        context "With a secured server" $ do
            around (withTestApp helloCtx unitCtx) $ do
                let helloClient = hmacClient (Proxy @HelloEndpoint)
                let streamClient = hmacClient (Proxy @StreamingEndpoint)
                let unsecuredHelloClient = client (Proxy @UnsecuredHelloEndpoint)

                it "should have the server authenticate the client's secured request with the same secret" $ \port -> do
                    result <- runHmacClient (helloClient "world" False "abcdef123789") (clientEnv port) hmacHelloClientAuth UserB
                    result `shouldBeASuccessWith` "hello from Just UserB to world: 987321fedcba"

                it "should have the server authenticate the client's secured streaming request with the same secret" $ \port -> do
                    result <- runHmacClient (streamClient (source ["abc", "", "123", "42", ""] :: SourceIO String)) (clientEnv port) hmacUnitClientAuth ()
                    result `shouldBeASuccessWith` "abc,123,42"

                it "should have the server reject the client's secured request with a different secret and respond with a 401 status code" $ \port -> do
                    result <- runHmacClient (helloClient "you" True "jdkmsqjdl") (clientEnv port) hmacUnitClientAuth ()
                    result `shouldBeAFailureWithStatus` unauthorized401

                it "should have the server reject the client's unsecured request and respond with a 401 status code" $ \port -> do
                    result <- runClientM (unsecuredHelloClient "me" False "00042") (clientEnv port)
                    result `shouldBeAFailureWithStatus` unauthorized401

                it "should have the HMAC signing failed before connection when the streaming request has failed during signing" $ \port -> do
                    result <- runHmacClient (streamClient (source ["hello", "", ""] <> fromStepT (Error "Failed!") :: SourceIO String)) (clientEnv port) hmacUnitClientAuth ()
                    result `shouldBe` Left (ConnectionError . SomeException $ RequestBodyInspectionFailed "Failed!")

        context "With an unsecured server" $ do
            around withUnsecuredTestApp $ do
                let helloClient = hmacClient (Proxy @HelloEndpoint)

                it "should have the server respond to the client and ignore the client request's HMAC signature" $ \port -> do
                    result <- runHmacClient (helloClient "world" True "abcdef123789") (clientEnv port) hmacHelloClientAuth UserA
                    result `shouldBeASuccessWith` "bye from Nothing: 987321fedcba"
