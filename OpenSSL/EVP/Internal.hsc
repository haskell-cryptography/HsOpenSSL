{-# LANGUAGE EmptyDataDecls           #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE CApiFFI                  #-}
module OpenSSL.EVP.Internal (
    Cipher(..),
    EVP_CIPHER,
    withCipherPtr,

    cipherIvLength,

    CipherCtx(..),
    EVP_CIPHER_CTX,
    newCipherCtx,
    withCipherCtxPtr,
    withNewCipherCtxPtr,

    CryptoMode(..),
    cipherSetPadding,
    cipherInitBS,
    cipherUpdateBS,
    cipherFinalBS,
    cipherStrictly,
    cipherLazily,

    Digest(..),
    EVP_MD,
    withMDPtr,

    DigestCtx(..),
    EVP_MD_CTX,
    withDigestCtxPtr,

    digestUpdateBS,
    digestFinalBS,
    digestFinal,
    digestStrictly,
    digestLazily,

    HmacCtx(..),
    HMAC_CTX,
    withHmacCtxPtr,

    hmacUpdateBS,
    hmacFinalBS,
    hmacLazily,

    VaguePKey(..),
    EVP_PKEY,
    PKey(..),
    createPKey,
    wrapPKeyPtr,
    withPKeyPtr,
    withPKeyPtr',
    unsafePKeyToPtr,
    touchPKey
  ) where

#include "HsOpenSSL.h"

import qualified Data.ByteString.Internal as B8
import qualified Data.ByteString.Unsafe as B8
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy.Char8 as L8
import qualified Data.ByteString.Lazy.Internal as L8
#if !MIN_VERSION_base(4,8,0)
import Control.Applicative ((<$>))
#endif
import Control.Exception (mask, mask_, bracket, onException)
import Foreign.C.Types (CChar)
#if MIN_VERSION_base(4,5,0)
import Foreign.C.Types (CInt(..), CUInt(..), CSize(..))
#else
import Foreign.C.Types (CInt, CUInt, CSize)
#endif
import Foreign.Ptr (Ptr, castPtr, FunPtr)
import Foreign.C.String (CString, peekCStringLen)
import Foreign.ForeignPtr
#if MIN_VERSION_base(4,4,0)
import Foreign.ForeignPtr.Unsafe as Unsafe
#else
import Foreign.ForeignPtr as Unsafe
#endif
import Foreign.Storable (Storable(..))
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Array (allocaArray)
import System.IO.Unsafe (unsafeInterleaveIO)
import OpenSSL.Utils


{- EVP_CIPHER ---------------------------------------------------------------- -}

-- |@Cipher@ is an opaque object that represents an algorithm of
-- symmetric cipher.
newtype Cipher     = Cipher (Ptr EVP_CIPHER)
data {-# CTYPE "openssl/evp.h" "EVP_CIPHER" #-} EVP_CIPHER

withCipherPtr :: Cipher -> (Ptr EVP_CIPHER -> IO a) -> IO a
withCipherPtr (Cipher cipherPtr) f = f cipherPtr

foreign import capi unsafe "HsOpenSSL.h HsOpenSSL_EVP_CIPHER_iv_length"
        _iv_length :: Ptr EVP_CIPHER -> CInt

cipherIvLength :: Cipher -> Int
cipherIvLength (Cipher cipherPtr) = fromIntegral $ _iv_length cipherPtr

{- EVP_CIPHER_CTX ------------------------------------------------------------ -}

newtype CipherCtx      = CipherCtx (ForeignPtr EVP_CIPHER_CTX)
data {-# CTYPE "openssl/evp.h" "EVP_CIPHER_CTX" #-} EVP_CIPHER_CTX

foreign import capi unsafe "openssl/evp.h EVP_CIPHER_CTX_new"
  _cipher_ctx_new :: IO (Ptr EVP_CIPHER_CTX)

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
foreign import capi unsafe "openssl/evp.h EVP_CIPHER_CTX_reset"
  _cipher_ctx_reset :: Ptr EVP_CIPHER_CTX -> IO ()
#else
foreign import capi unsafe "openssl/evp.h EVP_CIPHER_CTX_init"
  _cipher_ctx_reset :: Ptr EVP_CIPHER_CTX -> IO ()
#endif

foreign import capi unsafe "openssl/evp.h &EVP_CIPHER_CTX_free"
  _cipher_ctx_free :: FunPtr (Ptr EVP_CIPHER_CTX -> IO ())

foreign import capi unsafe "openssl/evp.h EVP_CIPHER_CTX_free"
  _cipher_ctx_free' :: Ptr EVP_CIPHER_CTX -> IO ()

foreign import capi unsafe "HsOpenSSL.h HsOpenSSL_EVP_CIPHER_CTX_block_size"
  _cipher_ctx_block_size :: Ptr EVP_CIPHER_CTX -> CInt

newCipherCtx :: IO CipherCtx
newCipherCtx = mask_ $ do
  ctx <- newForeignPtr _cipher_ctx_free =<< failIfNull =<< _cipher_ctx_new
  withForeignPtr ctx _cipher_ctx_reset
  return $ CipherCtx ctx

withCipherCtxPtr :: CipherCtx -> (Ptr EVP_CIPHER_CTX -> IO a) -> IO a
withCipherCtxPtr (CipherCtx ctx) = withForeignPtr ctx

withNewCipherCtxPtr :: (Ptr EVP_CIPHER_CTX -> IO a) -> IO a
withNewCipherCtxPtr f =
  bracket (failIfNull =<< _cipher_ctx_new) _cipher_ctx_free' $ \ p -> do
    _cipher_ctx_reset p
    f p

{- encrypt/decrypt ----------------------------------------------------------- -}

-- |@CryptoMode@ represents instruction to 'cipher' and such like.
data CryptoMode = Encrypt | Decrypt

fromCryptoMode :: Num a => CryptoMode -> a
fromCryptoMode Encrypt = 1
fromCryptoMode Decrypt = 0

foreign import capi unsafe "openssl/evp.h EVP_CIPHER_CTX_set_padding"
  _SetPadding :: Ptr EVP_CIPHER_CTX -> CInt -> IO CInt

cipherSetPadding :: CipherCtx -> Int -> IO CipherCtx
cipherSetPadding ctx pad
  = do withCipherCtxPtr ctx $ \ctxPtr ->
           _SetPadding ctxPtr (fromIntegral pad)
               >>= failIf_ (/= 1)
       return ctx

foreign import capi unsafe "openssl/evp.h EVP_CipherInit"
        _CipherInit :: Ptr EVP_CIPHER_CTX
                    -> Ptr EVP_CIPHER
                    -> CString
                    -> CString
                    -> CInt
                    -> IO CInt

cipherInitBS :: Cipher
             -> B8.ByteString -- ^ key
             -> B8.ByteString -- ^ IV
             -> CryptoMode
             -> IO CipherCtx
cipherInitBS (Cipher c) key iv mode
    = do ctx <- newCipherCtx
         withCipherCtxPtr ctx $ \ ctxPtr ->
             B8.unsafeUseAsCString key $ \ keyPtr ->
                 B8.unsafeUseAsCString iv $ \ ivPtr ->
                     _CipherInit ctxPtr c keyPtr ivPtr (fromCryptoMode mode)
                          >>= failIf_ (/= 1)
         return ctx

foreign import capi unsafe "openssl/evp.h EVP_CipherUpdate"
  _CipherUpdate :: Ptr EVP_CIPHER_CTX -> Ptr CChar -> Ptr CInt
                -> Ptr CChar -> CInt -> IO CInt

cipherUpdateBS :: CipherCtx -> B8.ByteString -> IO B8.ByteString
cipherUpdateBS ctx inBS =
  withCipherCtxPtr ctx $ \ctxPtr ->
    B8.unsafeUseAsCStringLen inBS $ \(inBuf, inLen) ->
      let len = inLen + fromIntegral (_cipher_ctx_block_size ctxPtr) - 1 in
        B8.createAndTrim len $ \outBuf ->
          alloca $ \outLenPtr ->
            _CipherUpdate ctxPtr (castPtr outBuf) outLenPtr inBuf
                          (fromIntegral inLen)
              >>= failIf (/= 1)
              >>  fromIntegral <$> peek outLenPtr

foreign import capi unsafe "openssl/evp.h EVP_CipherFinal"
  _CipherFinal :: Ptr EVP_CIPHER_CTX -> Ptr CChar -> Ptr CInt -> IO CInt

cipherFinalBS :: CipherCtx -> IO B8.ByteString
cipherFinalBS ctx =
  withCipherCtxPtr ctx $ \ctxPtr ->
    let len = fromIntegral $ _cipher_ctx_block_size ctxPtr in
      B8.createAndTrim len $ \outBuf ->
        alloca $ \outLenPtr ->
          _CipherFinal ctxPtr (castPtr outBuf) outLenPtr
            >>= failIf (/= 1)
            >>  fromIntegral <$> peek outLenPtr

cipherStrictly :: CipherCtx -> B8.ByteString -> IO B8.ByteString
cipherStrictly ctx input = do
  output'  <- cipherUpdateBS ctx input
  output'' <- cipherFinalBS ctx
  return $ B8.append output' output''

cipherLazily :: CipherCtx -> L8.ByteString -> IO L8.ByteString
cipherLazily ctx (L8.Empty) =
  cipherFinalBS ctx >>= return . L8.fromChunks . return
cipherLazily ctx (L8.Chunk x xs) = do
  y  <- cipherUpdateBS ctx x
  ys <- unsafeInterleaveIO $ cipherLazily ctx xs
  return $ L8.Chunk y ys

{- EVP_MD -------------------------------------------------------------------- -}

-- |@Digest@ is an opaque object that represents an algorithm of
-- message digest.
newtype Digest = Digest (Ptr EVP_MD)
data {-# CTYPE "openssl/evp.h" "EVP_MD" #-} EVP_MD

withMDPtr :: Digest -> (Ptr EVP_MD -> IO a) -> IO a
withMDPtr (Digest mdPtr) f = f mdPtr

{- EVP_MD_CTX ---------------------------------------------------------------- -}

newtype DigestCtx  = DigestCtx (ForeignPtr EVP_MD_CTX)
data {-# CTYPE "openssl/evp.h" "EVP_MD_CTX" #-}  EVP_MD_CTX


#if OPENSSL_VERSION_NUMBER >= 0x10100000L
foreign import capi unsafe "openssl/evp.h EVP_MD_CTX_new"
  _md_ctx_new :: IO (Ptr EVP_MD_CTX)
foreign import capi unsafe "openssl/evp.h EVP_MD_CTX_reset"
  _md_ctx_reset :: Ptr EVP_MD_CTX -> IO ()
foreign import capi unsafe "openssl/evp.h &EVP_MD_CTX_free"
  _md_ctx_free :: FunPtr (Ptr EVP_MD_CTX -> IO ())
#else
foreign import capi unsafe "openssl/evp.h EVP_MD_CTX_create"
  _md_ctx_new :: IO (Ptr EVP_MD_CTX)
foreign import capi unsafe "openssl/evp.h EVP_MD_CTX_init"
  _md_ctx_reset :: Ptr EVP_MD_CTX -> IO ()
foreign import capi unsafe "openssl/evp.h &EVP_MD_CTX_destroy"
  _md_ctx_free :: FunPtr (Ptr EVP_MD_CTX -> IO ())
#endif

newDigestCtx :: IO DigestCtx
newDigestCtx = mask_ $ do
  ctx <- newForeignPtr _md_ctx_free =<< failIfNull =<< _md_ctx_new
  withForeignPtr ctx _md_ctx_reset
  return $ DigestCtx ctx

withDigestCtxPtr :: DigestCtx -> (Ptr EVP_MD_CTX -> IO a) -> IO a
withDigestCtxPtr (DigestCtx ctx) = withForeignPtr ctx

{- digest -------------------------------------------------------------------- -}

foreign import capi unsafe "openssl/evp.h EVP_DigestInit"
  _DigestInit :: Ptr EVP_MD_CTX -> Ptr EVP_MD -> IO CInt

digestInit :: Digest -> IO DigestCtx
digestInit (Digest md) = do
  ctx <- newDigestCtx
  withDigestCtxPtr ctx $ \ctxPtr ->
    _DigestInit ctxPtr md
      >>= failIf_ (/= 1)
      >>  return ctx

foreign import capi unsafe "openssl/evp.h EVP_DigestUpdate"
  _DigestUpdate :: Ptr EVP_MD_CTX -> Ptr CChar -> CSize -> IO CInt

digestUpdateBS :: DigestCtx -> B8.ByteString -> IO ()
digestUpdateBS ctx bs =
  withDigestCtxPtr ctx $ \ctxPtr ->
    B8.unsafeUseAsCStringLen bs $ \(buf, len) ->
      _DigestUpdate ctxPtr buf (fromIntegral len)
        >>= failIf (/= 1)
        >>  return ()

foreign import capi unsafe "openssl/evp.h EVP_DigestFinal"
  _DigestFinal :: Ptr EVP_MD_CTX -> Ptr CChar -> Ptr CUInt -> IO CInt

digestFinalBS :: DigestCtx -> IO B8.ByteString
digestFinalBS ctx =
  withDigestCtxPtr ctx $ \ctxPtr ->
    B8.createAndTrim (#const EVP_MAX_MD_SIZE) $ \bufPtr ->
      alloca $ \bufLenPtr -> do
        _DigestFinal ctxPtr (castPtr bufPtr) bufLenPtr >>= failIf_ (/= 1)
        fromIntegral <$> peek bufLenPtr

digestFinal :: DigestCtx -> IO String
digestFinal ctx =
  withDigestCtxPtr ctx $ \ctxPtr ->
    allocaArray (#const EVP_MAX_MD_SIZE) $ \bufPtr ->
      alloca $ \bufLenPtr -> do
        _DigestFinal ctxPtr bufPtr bufLenPtr >>= failIf_ (/= 1)
        bufLen <- fromIntegral <$> peek bufLenPtr
        peekCStringLen (bufPtr, bufLen)

digestStrictly :: Digest -> B8.ByteString -> IO DigestCtx
digestStrictly md input = do
  ctx <- digestInit md
  digestUpdateBS ctx input
  return ctx

digestLazily :: Digest -> L8.ByteString -> IO DigestCtx
digestLazily md lbs = do
  ctx <- digestInit md
  mapM_ (digestUpdateBS ctx) $ L8.toChunks lbs
  return ctx

{- HMAC ---------------------------------------------------------------------- -}
newtype HmacCtx = HmacCtx (ForeignPtr HMAC_CTX)
data {-# CTYPE "openssl/hmac.h" "HMAC_CTX" #-} HMAC_CTX

foreign import capi unsafe "HsOpenSSL.h HsOpenSSL_HMAC_CTX_new"
  _hmac_ctx_new :: IO (Ptr HMAC_CTX)

foreign import capi unsafe "openssl/hmac.h HMAC_Init"
  _hmac_init :: Ptr HMAC_CTX -> Ptr () -> CInt -> Ptr EVP_MD -> IO CInt

foreign import capi unsafe "openssl/hmac.h HMAC_Update"
  _hmac_update :: Ptr HMAC_CTX -> Ptr CChar -> CInt -> IO CInt

foreign import capi unsafe "openssl/hmac.h HMAC_Final"
  _hmac_final :: Ptr HMAC_CTX -> Ptr CChar -> Ptr CInt -> IO CUInt

foreign import capi unsafe "HsOpenSSL &HsOpenSSL_HMAC_CTX_free"
  _hmac_ctx_free :: FunPtr (Ptr HMAC_CTX -> IO ())

newHmacCtx :: IO HmacCtx
newHmacCtx = do
    ctxPtr <- _hmac_ctx_new
    HmacCtx <$> newForeignPtr _hmac_ctx_free ctxPtr

withHmacCtxPtr :: HmacCtx -> (Ptr HMAC_CTX -> IO a) -> IO a
withHmacCtxPtr (HmacCtx ctx) = withForeignPtr ctx

hmacInit :: Digest -> B8.ByteString -> IO HmacCtx
hmacInit (Digest md) key = do
  ctx <- newHmacCtx
  withHmacCtxPtr ctx $ \ctxPtr ->
    B8.unsafeUseAsCStringLen key $ \(keyPtr, keyLen) ->
      _hmac_init ctxPtr (castPtr keyPtr) (fromIntegral keyLen) md
        >>= failIf_ (/= 1)
        >> return ctx

hmacUpdateBS :: HmacCtx -> B8.ByteString -> IO ()
hmacUpdateBS ctx bs = withHmacCtxPtr ctx $ \ctxPtr -> do
  B8.unsafeUseAsCStringLen bs $ \(buf, len) ->
    _hmac_update ctxPtr (castPtr buf) (fromIntegral len)
      >>= failIf_ (/= 1)

hmacFinalBS :: HmacCtx -> IO B8.ByteString
hmacFinalBS ctx =
  withHmacCtxPtr ctx $ \ctxPtr ->
    B8.createAndTrim (#const EVP_MAX_MD_SIZE) $ \bufPtr ->
      alloca $ \bufLenPtr -> do
        _hmac_final ctxPtr (castPtr bufPtr) bufLenPtr >>= failIf_ (/= 1)
        fromIntegral <$> peek bufLenPtr

hmacLazily :: Digest -> B8.ByteString -> L8.ByteString -> IO HmacCtx
hmacLazily md key lbs = do
  ctx <- hmacInit md key
  mapM_ (hmacUpdateBS ctx) $ L8.toChunks lbs
  return ctx

{- EVP_PKEY ------------------------------------------------------------------ -}

-- | VaguePKey is a 'ForeignPtr' to 'EVP_PKEY', that is either public
-- key or a ker pair. We can't tell which at compile time.
newtype VaguePKey = VaguePKey (ForeignPtr EVP_PKEY)
data {-# CTYPE "openssl/evp.h" "EVP_PKEY" #-} EVP_PKEY

-- | Instances of class 'PKey' can be converted back and forth to
-- 'VaguePKey'.
class PKey k where
    -- | Wrap the key (i.g. RSA) into 'EVP_PKEY'.
    toPKey        :: k -> IO VaguePKey

    -- | Extract the concrete key from the 'EVP_PKEY'. Returns
    -- 'Nothing' if the type mismatches.
    fromPKey      :: VaguePKey -> IO (Maybe k)

    -- | Do the same as EVP_PKEY_size().
    pkeySize      :: k -> Int

    -- | Return the default digesting algorithm for the key.
    pkeyDefaultMD :: k -> IO Digest

foreign import capi unsafe "openssl/evp.h EVP_PKEY_new"
  _pkey_new :: IO (Ptr EVP_PKEY)

foreign import capi unsafe "openssl/evp.h &EVP_PKEY_free"
  _pkey_free :: FunPtr (Ptr EVP_PKEY -> IO ())

foreign import capi unsafe "openssl/evp.h EVP_PKEY_free"
  _pkey_free' :: Ptr EVP_PKEY -> IO ()

wrapPKeyPtr :: Ptr EVP_PKEY -> IO VaguePKey
wrapPKeyPtr = fmap VaguePKey . newForeignPtr _pkey_free

createPKey :: (Ptr EVP_PKEY -> IO a) -> IO VaguePKey
createPKey f = mask $ \restore -> do
  ptr <- _pkey_new >>= failIfNull
  (restore $ f ptr >> return ()) `onException` _pkey_free' ptr
  wrapPKeyPtr ptr

withPKeyPtr :: VaguePKey -> (Ptr EVP_PKEY -> IO a) -> IO a
withPKeyPtr (VaguePKey pkey) = withForeignPtr pkey

withPKeyPtr' :: PKey k => k -> (Ptr EVP_PKEY -> IO a) -> IO a
withPKeyPtr' k f = do
  pk <- toPKey k
  withPKeyPtr pk f

unsafePKeyToPtr :: VaguePKey -> Ptr EVP_PKEY
unsafePKeyToPtr (VaguePKey pkey) = Unsafe.unsafeForeignPtrToPtr pkey

touchPKey :: VaguePKey -> IO ()
touchPKey (VaguePKey pkey) = touchForeignPtr pkey
