module Main (main) where

import Control.Monad.IO.Class
import qualified Network.Wai as Wai
import Network.Wai.Handler.Warp (run)
import Servant
import Servant.Auth.Hmac.Crypto
import Servant.Auth.Hmac.Secure

data MyUser
    = UserA
    | UserB
    deriving stock (Show)

type MyApi =
    HmacAuthed MyUser :> "messages" :> ReqBody '[PlainText] String :> Post '[PlainText] String
        :<|> HmacAuthed MyUser :> "messages" :> Get '[PlainText] String

myApi :: Proxy MyApi
myApi = Proxy

postMessage :: MyUser -> String -> Handler String
postMessage usr msg = do
    liftIO . putStrLn $ "Message from " <> show usr <> ": " <> msg
    pure "Message printed!"

getMessages :: MyUser -> Handler String
getMessages usr = pure $ "Nothing else for " <> show usr

myServer :: Server MyApi
myServer = postMessage :<|> getMessages

serverSideAuth :: HmacServerSideAuth MyUser
serverSideAuth =
    HmacServerSideAuth
        { hssaSign = signSHA256
        , hssaIdentifyUser = \req -> case lookup "X-User" (Wai.requestHeaders req) of
            Just "user-a" -> pure $ Just UserA
            Just "user-b" -> pure $ Just UserB
            _ -> pure Nothing
        , hssaSecretKey = \case
            UserA -> SecretKey "User-A-Secret"
            UserB -> SecretKey "Secret-from-User-B"
        }

myApp :: Application
myApp =
    serveWithContext
        myApi
        (serverSideAuth :. EmptyContext)
        myServer

main :: IO ()
main = run 8080 myApp
