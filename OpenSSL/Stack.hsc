{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE CApiFFI                  #-}
module OpenSSL.Stack
    ( STACK
    , mapStack
    , withStack
    , withForeignStack
    )
    where
#include "HsOpenSSL.h"
import           Control.Exception
import           Foreign
import           Foreign.C


data STACK


#if OPENSSL_VERSION_NUMBER >= 0x10100000L
foreign import capi unsafe "openssl/safestack.h OPENSSL_sk_new_null"
        skNewNull :: IO (Ptr STACK)

foreign import capi unsafe "openssl/safestack.h OPENSSL_sk_free"
        skFree :: Ptr STACK -> IO ()

foreign import capi unsafe "openssl/safestack.h OPENSSL_sk_push"
        skPush :: Ptr STACK -> Ptr () -> IO ()

foreign import capi unsafe "openssl/safestack.h OPENSSL_sk_num"
        skNum :: Ptr STACK -> IO CInt

foreign import capi unsafe "openssl/safestack.h OPENSSL_sk_value"
        skValue :: Ptr STACK -> CInt -> IO (Ptr ())
#else
foreign import capi unsafe "openssl/safestack.h sk_new_null"
        skNewNull :: IO (Ptr STACK)

foreign import capi unsafe "openssl/safestack.h sk_free"
        skFree :: Ptr STACK -> IO ()

foreign import capi unsafe "openssl/safestack.h sk_push"
        skPush :: Ptr STACK -> Ptr () -> IO ()

foreign import capi unsafe "openssl/safestack.h sk_num"
        skNum :: Ptr STACK -> IO CInt

foreign import capi unsafe "openssl/safestack.h sk_value"
        skValue :: Ptr STACK -> CInt -> IO (Ptr ())
#endif

mapStack :: (Ptr a -> IO b) -> Ptr STACK -> IO [b]
mapStack m st
    = do num <- skNum st
         mapM (\ i -> fmap castPtr (skValue st i) >>= m)
                  $ take (fromIntegral num) [0..]


newStack :: [Ptr a] -> IO (Ptr STACK)
newStack values
    = do st <- skNewNull
         mapM_ (skPush st . castPtr) values
         return st


withStack :: [Ptr a] -> (Ptr STACK -> IO b) -> IO b
withStack values
    = bracket (newStack values) skFree


withForeignStack :: (fp -> Ptr obj)
                 -> (fp -> IO ())
                 -> [fp]
                 -> (Ptr STACK -> IO ret)
                 -> IO ret
withForeignStack unsafeFpToPtr touchFp fps action
    = do ret <- withStack (map unsafeFpToPtr fps) action
         mapM_ touchFp fps
         return ret
