{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE CApiFFI #-}
-- |Encoding and decoding of RSA keys using the ASN.1 DER format
module OpenSSL.DER
    ( toDERPub
    , fromDERPub
    , toDERPriv
    , fromDERPriv
    )
    where

#if !MIN_VERSION_base(4,8,0)
import Control.Applicative ((<$>))
#endif
import           OpenSSL.RSA                (RSA, RSAKey, RSAKeyPair, RSAPubKey,
                                             absorbRSAPtr, withRSAPtr)

import           Data.ByteString            (ByteString)
import qualified Data.ByteString            as B  (useAsCStringLen)
import qualified Data.ByteString.Internal   as BI (createAndTrim)
import           Foreign.Ptr                (Ptr, nullPtr, castPtr)
import           Foreign.C.Types            (CLong(..), CInt(..))
import           Foreign.Marshal.Alloc      (alloca)
import           Foreign.Storable           (poke)
import           GHC.Word                   (Word8)
import           System.IO.Unsafe           (unsafePerformIO)

type CDecodeFun = Ptr (Ptr RSA) -> Ptr (Ptr Word8) -> CLong -> IO (Ptr RSA)
type CEncodeFun = Ptr RSA -> Ptr (Ptr Word8) -> IO CInt

foreign import capi unsafe "HsOpenSSL.h d2i_RSAPublicKey"
  _fromDERPub :: CDecodeFun

foreign import capi unsafe "HsOpenSSL.h i2d_RSAPublicKey"
  _toDERPub :: CEncodeFun

foreign import capi unsafe "HsOpenSSL.h d2i_RSAPrivateKey"
  _fromDERPriv :: CDecodeFun

foreign import capi unsafe "HsOpenSSL.h i2d_RSAPrivateKey"
  _toDERPriv :: CEncodeFun

-- | Generate a function that decodes a key from ASN.1 DER format
makeDecodeFun :: RSAKey k => CDecodeFun -> ByteString -> Maybe k
makeDecodeFun fun bs = unsafePerformIO . usingConvedBS $ \(csPtr, ci) -> do
  -- When you pass a null pointer to this function, it will allocate the memory
  -- space required for the RSA key all by itself.  It will be freed whenever
  -- the haskell object is garbage collected, as they are stored in ForeignPtrs
  -- internally.
  rsaPtr <- fun nullPtr (castPtr csPtr) ci
  -- CString is represented as a void* in C and the C compiler whines about
  -- a bad pointer conversion in d2i_* functions. So we declare
  -- the CDecodeFun to accept Ptr Word8 and perform the castPtr here.
  if rsaPtr == nullPtr then return Nothing else absorbRSAPtr rsaPtr
  where usingConvedBS io = B.useAsCStringLen bs $ \(cs, len) ->
          alloca $ \csPtr -> poke csPtr cs >> io (csPtr, fromIntegral len)

-- | Generate a function that encodes a key in ASN.1 DER format
makeEncodeFun :: RSAKey k => CEncodeFun -> k -> ByteString
makeEncodeFun fun k = unsafePerformIO $ do
  -- When you pass a null pointer to this function, it will only compute the
  -- required buffer size.  See https://www.openssl.org/docs/faq.html#PROG3
  requiredSize <- withRSAPtr k $ flip fun nullPtr
  -- It’s too sad BI.createAndTrim is considered internal, as it does a great
  -- job here.  See https://hackage.haskell.org/package/bytestring-0.9.1.4/docs/Data-ByteString-Internal.html#v%3AcreateAndTrim
  BI.createAndTrim (fromIntegral requiredSize) $ \ptr ->
    alloca $ \pptr ->
      (fromIntegral <$>) . withRSAPtr k $ \key ->
        poke pptr ptr >> fun key pptr

-- | Dump a public key to ASN.1 DER format
toDERPub :: RSAKey k
         => k          -- ^ You can pass either 'RSAPubKey' or 'RSAKeyPair'
                       --   because both contain the necessary information.
         -> ByteString -- ^ The public key information encoded in ASN.1 DER
toDERPub = makeEncodeFun _toDERPub

-- | Parse a public key from ASN.1 DER format
fromDERPub :: ByteString -> Maybe RSAPubKey
fromDERPub = makeDecodeFun _fromDERPub

-- | Dump a private key to ASN.1 DER format
toDERPriv :: RSAKeyPair -> ByteString
toDERPriv = makeEncodeFun _toDERPriv

-- | Parse a private key from ASN.1 DER format
fromDERPriv :: RSAKey k
            => ByteString -- ^ The private key information encoded in ASN.1 DER
            -> Maybe k    -- ^ This can return either 'RSAPubKey' or
                          --   'RSAKeyPair' because there’s sufficient
                          --   information for both.
fromDERPriv = makeDecodeFun _fromDERPriv
