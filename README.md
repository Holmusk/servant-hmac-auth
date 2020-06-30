# servant-hmac-auth

[![Hackage](https://img.shields.io/hackage/v/servant-hmac-auth.svg)](https://hackage.haskell.org/package/servant-hmac-auth)
[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Stackage Lts](http://stackage.org/package/servant-hmac-auth/badge/lts)](http://stackage.org/lts/package/servant-hmac-auth)
[![Stackage Nightly](http://stackage.org/package/servant-hmac-auth/badge/nightly)](http://stackage.org/nightly/package/servant-hmac-auth)

Servant authentication with HMAC

## Example

In this section, we will introduce the client-server example.
To run it locally you can:

```shell
$ cabal new-build
$ cabal new-exec readme
```

So,it will run this on your machine.

### Setting up

Since this tutorial is written using Literate Haskell, first, let's write all necessary pragmas and imports.

```haskell
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE TypeApplications           #-}
{-# LANGUAGE TypeOperators              #-}

import Control.Concurrent (forkIO, threadDelay)
import Data.Aeson (FromJSON, ToJSON)
import Data.Proxy (Proxy (..))
import GHC.Generics (Generic)
import Network.HTTP.Client (defaultManagerSettings, newManager)
import Network.Wai.Handler.Warp (run)
import Servant.API ((:>), Get, JSON)
import Servant.Client (BaseUrl (..), Scheme (..), ClientError, mkClientEnv)
import Servant.Server (Application, Server, serveWithContext)

import Servant.Auth.Hmac (HmacAuth, HmacClientM, SecretKey (..), defaultHmacSettings,
                          hmacAuthServerContext, hmacClient, runHmacClient, signSHA256)
```

### Server

Let's define our `TheAnswer` data type with the necessary instances for it.

```haskell
newtype TheAnswer = TheAnswer Int
    deriving (Show, Generic, FromJSON, ToJSON)

getTheAnswer :: TheAnswer
getTheAnswer = TheAnswer 42
```

Now, let's introduce a very simple protected endpoint. The value of `TheAnswer`
data type will be the value that our API endpoint returns. It our case we want
it to return the number `42` for all signed requests.

```haskell
type TheAnswerToEverythingUnprotectedAPI = "answer" :> Get '[JSON] TheAnswer
type TheAnswerToEverythingAPI = HmacAuth :> TheAnswerToEverythingUnprotectedAPI
```

As you can see this endpoint is protected by `HmacAuth`.

And now our server:

```haskell
server42 :: Server TheAnswerToEverythingAPI
server42 = \_ -> pure getTheAnswer
```

Now we can turn `server` into an actual webserver:

```haskell
topSecret :: SecretKey
topSecret = SecretKey "top-secret"

app42 :: Application
app42 = serveWithContext
    (Proxy @TheAnswerToEverythingAPI)
    (hmacAuthServerContext signSHA256 topSecret)
    server42
```

### Client

Now let's implement client that queries our server and signs every request
automatically.

```haskell
client42 :: HmacClientM TheAnswer
client42 = hmacClient @TheAnswerToEverythingUnprotectedAPI
```

Now we need to write function that runs our client:

```haskell
runClient :: SecretKey -> HmacClientM a -> IO (Either ClientError a)
runClient sk client = do
    manager <- newManager defaultManagerSettings
    let env = mkClientEnv manager $ BaseUrl Http "localhost" 8080 ""
    runHmacClient (defaultHmacSettings sk) env client
```

### Main

And we're able to run our server in separate thread and perform two quiries:

* Properly signed
* Signed with different key

```haskell
main :: IO ()
main = do
    _ <- forkIO $ run 8080 app42

    print =<< runClient topSecret client42
    print =<< runClient (SecretKey "wrong!") client42

    threadDelay $ 10 ^ (6 :: Int)
```
