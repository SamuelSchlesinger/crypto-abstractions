{-# OPTIONS_HADDOCK show-extensions  #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE TypeOperators #-}
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

{-|
Module: Crypto.Abstractions
Description: A number of cryptographic interfaces
Copyright: (c) Samuel Schlesinger, 2021
Maintainer: sgschlesinger@gmail.com
License: MIT

This module contains interfaces for symmetric and asymmetric encryption, as well as digital
signature protocols.
-}

module Crypto.Abstractions
  ( 
    -- * Public + Private Keys
    --
    -- | Public key encryption is important for establishing identity and creating secure,
    -- private communication between network actors. In many systems, public keys
    -- are used as a sort of ID, and private keys are used in lieu of passwords.
    PublicKeyProtocol(..)

    -- * Digital Signatures
    --
    -- | Digital signatures are important mechanisms, in the context of a public key protocol,
    -- to prove to another that you've seen, and perhaps assented to, some piece of data.
  , DigitalSignatureProtocol(..)

    -- * Encryption and Decryption
    --
    -- | Across asymmetric and symmetric encryption protocols, there are common aspects which are embodied
    -- in this interface.
  , EncryptionProtocol(..)

    -- | An interface for asymmetric encryption. This is based off of the public key interface,
    -- and allows you to encrypt a message for only a specific reader, given their public key.
  , AsymmetricEncryptionProtocol(..)
  
    -- | An interface for symmetric encryption, which allows one to encrypt and decrypt based off of
    -- a shared key.
  , SymmetricEncryptionProtocol(..)
  
    -- | A derivative asymmetric encryption protocol which layers an asymmetric protocol on
    -- top of a symmetric one to achieve the performance characteristics of the symmetric protocol
    -- in an asymmetric protocol.
  , PGP
    -- | The 'Environment' of the 'PGP' protocol:
  , MonadPGP(..)

    -- | A derivative asymmetric encryption protocol which composes two asymmetric protocols on top
    -- of one another to achieve each of their maximum security characteristics (hopefully).
  , (:>>:)
    -- | The 'Environment' of the '(:>>:)' protocol:
  , MonadAsymmetricProduct(..)

    -- | A witness for a constraint, needed for technical reasons. 
  , Dict(..)
  ) where

import Control.Monad ((>=>)) 
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

instance (Encryptable asym (Key sym), SymmetricEncryptionProtocol sym, AsymmetricEncryptionProtocol asym) => PublicKeyProtocol (PGP asym sym) where
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
  pgpEnv :: Dict (Environment (PGP asym sym) m) -> Dict (Environment asym m, Environment sym m)

-- |
-- === Summary
-- A dictionary for a given constraint, or perhaps a witness of it.
--
-- === Discussion
-- This is also defined in the lovely constraints library but I am loath to depend
-- on another package for something so simple.
data Dict c where
  Dict :: c => Dict c

instance (Encryptable asym (Key sym), SymmetricEncryptionProtocol sym, AsymmetricEncryptionProtocol asym) => AsymmetricEncryptionProtocol (PGP asym sym) where
  encryptFor :: forall m a. (Environment (PGP asym sym) m, Encryptable (PGP asym sym) a) => PublicKey (PGP asym sym) -> a -> m (Message (PGP asym sym)) 
  encryptFor publicKey a = do
    key <- genKey @asym @sym
    case pgpEnv (Dict @(Environment (PGP asym sym) m)) of
      Dict -> do
        asymmetricallyEncryptedKey <- encryptFor @asym (coerce publicKey) key
        symmetricallyEncryptedBody <- encryptWith key a
        pure PGPMessage{..}
  decryptAs :: forall m a. (Environment (PGP asym sym) m, Encryptable (PGP asym sym) a) => PrivateKey (PGP asym sym) -> Message (PGP asym sym) -> m (Either (EncryptionError (PGP asym sym)) a)
  decryptAs privateKey (PGPMessage asymKey symBody) =
    case pgpEnv (Dict @(Environment (PGP asym sym) m)) of
      Dict ->
        decryptAs @asym (coerce privateKey) asymKey
          >>= \case
            Left err -> pure (Left $ PGPAsymmetricEncryptionError err)
            Right key -> decryptWith key symBody >>= \case
              Left err -> pure (Left $ PGPSymmetricEncryptionError err)
              Right a -> pure (Right a)

-- |
-- === Summary
-- An asymmetric protocol which layers one asymmetric protocol over another. It will combine their security guarantees.
--
-- === Discussion
-- I don't know this to be useful, though I know it to be definable.
data asym :>>: asym'

instance (Encryptable asym' (Message asym), AsymmetricEncryptionProtocol asym, AsymmetricEncryptionProtocol asym') => PublicKeyProtocol (asym :>>: asym') where
  data Settings (asym :>>: asym') = Settings asym :>?>: Settings asym'
  data PublicKey (asym :>>: asym') = PublicKey asym :>!>: PublicKey asym'
  data PrivateKey (asym :>>: asym') = PrivateKey asym :>.>: PrivateKey asym'
  generate (asymSettings :>?>: asym'Settings) = (:>.>:) <$> generate asymSettings <*> generate asym'Settings
  getSettings (private :>.>: private') = getSettings private :>?>: getSettings private'
  getPublicKey (private :>.>: private') = getPublicKey private :>!>: getPublicKey private'

class Monad m => MonadAsymmetricProduct asym asym' m where
  productEnv :: Dict (Environment (asym :>>: asym') m) -> Dict (Environment asym m, Environment asym' m)

class (Encryptable asym x, Encryptable asym' x) => DoubleEncryptable asym asym' x
instance (Encryptable asym x, Encryptable asym' x) => DoubleEncryptable asym asym' x

instance (Encryptable asym' (Message asym), AsymmetricEncryptionProtocol asym, AsymmetricEncryptionProtocol asym') => EncryptionProtocol (asym :>>: asym') where
  type Environment (asym :>>: asym') = MonadAsymmetricProduct asym asym'
  newtype Message (asym :>>: asym') = AsymmetricProductMessage { unAsymmetricProductMessage :: Message asym' }
  type Encryptable (asym :>>: asym') = DoubleEncryptable asym asym'
  data EncryptionError (asym :>>: asym') = AsymmetricProductFirstProtocolError (EncryptionError asym) | AsymmetricProductSecondProtocolError (EncryptionError asym')
  
instance (Encryptable asym' (Message asym), AsymmetricEncryptionProtocol asym, AsymmetricEncryptionProtocol asym') => AsymmetricEncryptionProtocol (asym :>>: asym') where
  encryptFor :: forall m a. (Environment (asym :>>: asym') m, Encryptable (asym :>>: asym') a) => PublicKey (asym :>>: asym') -> a -> m (Message (asym :>>: asym'))
  encryptFor (publicKey :>!>: publicKey') = case productEnv @asym @asym' @m Dict of
    Dict -> fmap (fmap AsymmetricProductMessage) $ encryptFor publicKey >=> encryptFor publicKey'
  decryptAs :: forall m a. (Environment (asym :>>: asym') m, Encryptable (asym :>>: asym') a) => PrivateKey (asym :>>: asym') -> Message (asym :>>: asym') -> m (Either (EncryptionError (asym :>>: asym')) a)
  decryptAs (privateKey :>.>: privateKey') = case productEnv @asym @asym' @m Dict of
    Dict -> \(unAsymmetricProductMessage -> message') -> do
      mMessage <- decryptAs privateKey' message'
      case mMessage of
        Left err -> pure (Left $ AsymmetricProductSecondProtocolError err)
        Right message -> either (Left . AsymmetricProductFirstProtocolError) pure <$> decryptAs privateKey message

-- TODO(sam)
-- === Summary
-- An asymmetric protocol which allows one to choose between two different schemes at will.
data asym :+: asym'
