module Main (main) where

import Data.Proxy
import Network.HTTP.Client (defaultManagerSettings, newManager)
import Servant.API
import Servant.Auth.Hmac.Crypto
import Servant.Auth.Hmac.Secure
import Servant.Client
import qualified Servant.Client.Core as Client

data MyUser
    = UserA
    | UserB
    deriving stock (Show)

type MyApi =
    HmacAuthed MyUser :> "messages" :> ReqBody '[PlainText] String :> Post '[PlainText] String
        :<|> HmacAuthed MyUser :> "messages" :> Get '[PlainText] String

myApi :: Proxy MyApi
myApi = Proxy

postMessage :: String -> HmacClientM MyUser String
getMessages :: HmacClientM MyUser String
(postMessage :<|> getMessages) = hmacClient myApi

clientSideAuth :: HmacClientSideAuth MyUser
clientSideAuth =
    HmacClientSideAuth
        { hcsaSign = signSHA256
        , hcsaUserRequest = \case
            UserA -> pure . Client.addHeader "X-User" ("user-a" :: String)
            UserB -> pure . Client.addHeader "X-User" ("user-b" :: String)
        , hcsaSecretKey = \case
            UserA -> SecretKey "User-A-Secret"
            UserB -> SecretKey "Secret-from-User-B"
        }

main :: IO ()
main = do
    manager <- newManager defaultManagerSettings
    let clientEnv = mkClientEnv manager (BaseUrl Http "localhost" 8080 "")
    postResponse <- runHmacClient (postMessage "Hello!") clientEnv clientSideAuth UserA
    print postResponse
    getResponse <- runHmacClient getMessages clientEnv clientSideAuth UserB
    print getResponse
