{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE UndecidableSuperClasses #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE QuantifiedConstraints #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
module Crypto
  ( PublicKeyProtocol(..)
  , DigitalSignatureProtocol(..)
  , EncryptionProtocol(..)
  , AsymmetricEncryptionProtocol(..)
  , SymmetricEncryptionProtocol(..)
  , PGP
  , MonadPGP(..)
  ) where

import Data.Kind (Type, Constraint)
import Data.Coerce (coerce)

-- |
-- === Summary
-- An interface for protocols with public and private keys. 
-- [Wikipedia!](https://en.wikipedia.org/wiki/Public-key_cryptography)
--
-- === Laws
-- [@Settings Preservation@]:
--
-- @
--   getSettings \<$\> generate s == pure s
-- @
--
-- === Discussion
-- Presumably there is some information which is convenient to convey as part of the
-- static data, implied by the @protocol@ type, and there is some data which
-- is convenient to convey dynamically. For this purpose, the 'Settings' type
-- is added.
class PublicKeyProtocol protocol where
  data Settings protocol
  data PublicKey protocol
  data PrivateKey protocol
  generate :: Settings protocol -> IO (PrivateKey protocol)
  getSettings :: PrivateKey protocol -> Settings protocol
  getPublicKey :: PrivateKey protocol -> PublicKey protocol

-- |
-- === Summary
-- An interface for public key protocols which allow the creation and validation of
-- digital signatures. [Wikipedia!](https://en.wikipedia.org/wiki/Digital_signature)
--
-- === Laws
-- [@Digital Signature Correctness@]:
-- @
--   validate publicKey a (sign privateKey a) == True
-- @
--     if and only if
-- @
--   getPublicKey privateKey == publicKey
-- @
--
class PublicKeyProtocol protocol => DigitalSignatureProtocol protocol where
  -- | A signature of some thing, confirming that someone with a certain private
  -- key has signed it.
  data DigitalSignature protocol
  -- | The class of things which are able to be signed to produce a 'DigitalSignature'.
  type Signable protocol :: Type -> Constraint
  -- | Generates a digital signature based on the 'Signable' thing passed in.
  sign :: Signable protocol a => PrivateKey protocol -> a -> DigitalSignature protocol
  -- | Validates that the 'Signable' @a@ was signed by the private
  -- key associated with the 'PublicKey' passed into the function.
  validate :: Signable protocol a => PublicKey protocol -> a -> DigitalSignature protocol -> Bool

class (forall m. Environment protocol m => Monad m) => EncryptionProtocol protocol where
  -- | The type of messages used in this protocol
  data Message protocol
  -- | The class of things which can be encrypted into a 'Message'.
  type Encryptable protocol :: Type -> Constraint
  -- | Errors associated with decrypting using this protocol.
  data EncryptionError protocol
  -- | The types of environments in which you can perform the operations
  type Environment protocol :: (Type -> Type) -> Constraint

-- |
-- === Summary
-- An interface for public key protocols which allow for encryption/decryption.
-- [Wikipedia!](https://en.wikipedia.org/wiki/Encryption)
--
-- === Laws
-- [@Asymmetric Encryption Correctness@]:
-- @
--   decryptAs privateKey (encryptFor publicKey a) == Right a'
-- @
--     if and only if
-- @
--   getPublicKey privateKey == publicKey && a == a'
-- @
-- 
class (EncryptionProtocol protocol, PublicKeyProtocol protocol) => AsymmetricEncryptionProtocol protocol where
  -- | Encrypt a message which may only be decrypted with the private key associated with
  -- the given public key.
  encryptFor :: (Environment protocol m, Encryptable protocol a) => PublicKey protocol -> a -> m (Message protocol)
  -- | Decrypt a message using the given private key. This will only succeed if the message
  -- was encrypted for the public key corresponding to this private key.
  decryptAs :: (Environment protocol m, Encryptable protocol a) => PrivateKey protocol -> Message protocol -> m (Either (EncryptionError protocol) a)

-- |
-- === Summary
-- An interface for symmetric encryption/decryption, meaning that there is no concept of
-- public and private key, merely a key. [Wikipedia!](https://en.wikipedia.org/wiki/Symmetric-key_algorithm)
--
-- === Laws
-- [@Symmetric Encryption Correctness@]
-- @
--   decrypt key (encrypt key' a) == Right a'
-- @
-- if and only if
-- @
--   key' == key && a == a'
-- @
--
-- === Discussion
-- One can model this in a more unified way with public key encryption, but its sort of awkward and its
-- often desirable to use them in tandem. For these reasons, I modeled them separately. In particular,
-- if 'getPublicKey' is equal to 'id', these definitions reduce to one another.
class EncryptionProtocol protocol => SymmetricEncryptionProtocol protocol where
  -- | The key type used to encrypt data
  data Key protocol
  -- | Encrypt a message using the given 'Key'.
  encryptWith :: (Environment protocol m, Encryptable protocol a) => Key protocol ->  a -> m (Message protocol)
  decryptWith :: (Environment protocol m, Encryptable protocol a) => Key protocol -> Message protocol -> m (Either (EncryptionError protocol) a)

-- |
-- === Summary
-- A protocol which layers an asymmetric approach on top of a symmetric one. Its performance will
-- match the symmetric algorithm asymptotically assuming constant key size, but it is a public key
-- algorithm and so one can encrypt things for someone without key distribution.
--
-- === Discussion
-- Often, when using encryption, it is convenient to layer an asymmetric and a symmetric protocol to
-- achieve the desirable properties of a public key system while leveraging the performance
-- characeteristics of symmetric protocols.
data PGP asymmetricProtocol symmetricProtocol

instance (SymmetricEncryptionProtocol sym, AsymmetricEncryptionProtocol asym) => PublicKeyProtocol (PGP asym sym) where
  newtype Settings (PGP asym sym) = PGPSettings { asymmetricSettings :: Settings asym }
  newtype PublicKey (PGP asym sym) = PGPPublicKey { unPublicKey :: PublicKey asym }
  newtype PrivateKey (PGP asym sym) = PGPrivateKey { unPrivateKey :: PrivateKey asym }
  generate = coerce <$> generate
  getSettings = coerce . getSettings @asym . coerce
  getPublicKey = coerce . getPublicKey @asym . coerce

instance (Encryptable asym (Key sym), SymmetricEncryptionProtocol sym, AsymmetricEncryptionProtocol asym) => EncryptionProtocol (PGP asym sym) where
  data Message (PGP asym sym) = PGPMessage { asymmetricallyEncryptedKey :: Message asym, symmetricallyEncryptedBody :: Message sym }
  type Encryptable (PGP asym sym) = Encryptable sym
  data EncryptionError (PGP asym sym) = PGPSymmetricEncryptionError (EncryptionError sym) | PGPAsymmetricEncryptionError (EncryptionError asym)
  type Environment (PGP asym sym) = MonadPGP asym sym

class Monad m => MonadPGP asym sym m where
  genKey :: m (Key sym)
  asymEnv :: Dict (Environment (PGP asym sym) m) -> Dict (Environment asym m)
  symEnv :: Dict (Environment (PGP asym sym) m) -> Dict (Environment sym m)

data Dict c where
  Dict :: c => Dict c

instance (Encryptable asym (Key sym), SymmetricEncryptionProtocol sym, AsymmetricEncryptionProtocol asym) => AsymmetricEncryptionProtocol (PGP asym sym) where
  encryptFor :: forall m a. (Environment (PGP asym sym) m, Encryptable (PGP asym sym) a) => PublicKey (PGP asym sym) -> a -> m (Message (PGP asym sym)) 
  encryptFor publicKey a = do
    key <- genKey @asym @sym
    case (asymEnv (Dict @(Environment (PGP asym sym) m)), symEnv (Dict @(Environment (PGP asym sym) m))) of
      (Dict, Dict) -> do
        asymmetricallyEncryptedKey <- encryptFor @asym (coerce publicKey) key
        symmetricallyEncryptedBody <- encryptWith key a
        pure PGPMessage{..}
  decryptAs :: forall m a. (Environment (PGP asym sym) m, Encryptable (PGP asym sym) a) => PrivateKey (PGP asym sym) -> Message (PGP asym sym) -> m (Either (EncryptionError (PGP asym sym)) a)
  decryptAs privateKey (PGPMessage asymKey symBody) =
    case (asymEnv (Dict @(Environment (PGP asym sym) m)), symEnv (Dict @(Environment (PGP asym sym) m))) of
      (Dict, Dict) ->
        decryptAs @asym (coerce privateKey) asymKey
          >>= \case
            Left err -> pure (Left $ PGPAsymmetricEncryptionError err)
            Right key -> decryptWith key symBody >>= \case
              Left err -> pure (Left $ PGPSymmetricEncryptionError err)
              Right a -> pure (Right a)
