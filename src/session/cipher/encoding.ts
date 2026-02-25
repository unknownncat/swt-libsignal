import {
  type WhisperMessage,
  type PreKeyWhisperMessage,
  WhisperMessageCodec,
  PreKeyWhisperMessageCodec,
} from '../../proto'
import { ProtobufValidationError } from '../../errors/protobuf-validation-error'
import type { WhisperMessageProto, PreKeyWhisperMessageProto } from './types'

const MAX_PROTO_BYTES = 512 * 1024
const MAX_CIPHERTEXT_BYTES = 256 * 1024

function assertReasonableSize(name: string, value: Uint8Array, limit: number): void {
  if (value.length === 0) {
    throw new ProtobufValidationError(`${name} must not be empty`)
  }
  if (value.length > limit) {
    throw new ProtobufValidationError(`${name} exceeds maximum allowed size`)
  }
}

export class WhisperMessageEncoder {
  static encodeWhisperMessage(msg: WhisperMessageProto): Uint8Array {
    return WhisperMessageCodec.encode(msg)
  }

  static decodeWhisperMessage(buf: Uint8Array): WhisperMessageProto {
    if (buf.length === 0 || buf.length > MAX_PROTO_BYTES) {
      throw new ProtobufValidationError('WhisperMessage payload size is invalid')
    }

    const decoded = WhisperMessageCodec.decode(buf)
    this.validateWhisper(decoded)

    return {
      ephemeralKey: decoded.ephemeralKey,
      counter: decoded.counter,
      previousCounter: decoded.previousCounter,
      ciphertext: decoded.ciphertext,
    }
  }

  static encodePreKeyWhisperMessage(msg: PreKeyWhisperMessageProto): Uint8Array {
    return PreKeyWhisperMessageCodec.encode(msg)
  }

  static decodePreKeyWhisperMessage(buf: Uint8Array): PreKeyWhisperMessageProto {
    if (buf.length === 0 || buf.length > MAX_PROTO_BYTES) {
      throw new ProtobufValidationError('PreKeyWhisperMessage payload size is invalid')
    }

    const decoded = PreKeyWhisperMessageCodec.decode(buf)
    this.validatePreKey(decoded)

    const message: PreKeyWhisperMessageProto = {
      identityKey: decoded.identityKey,
      registrationId: decoded.registrationId,
      baseKey: decoded.baseKey,
      signedPreKeyId: decoded.signedPreKeyId,
      message: decoded.message,
    }

    if (typeof decoded.preKeyId === 'number') {
      message.preKeyId = decoded.preKeyId
    }

    return message
  }

  private static validateWhisper(message: WhisperMessage): asserts message is Required<WhisperMessage> {
    if (!message.ephemeralKey || !message.ciphertext) {
      throw new ProtobufValidationError('WhisperMessage missing required binary fields')
    }

    assertReasonableSize('WhisperMessage.ephemeralKey', message.ephemeralKey, 64)
    assertReasonableSize('WhisperMessage.ciphertext', message.ciphertext, MAX_CIPHERTEXT_BYTES)

    if (typeof message.counter !== 'number' || typeof message.previousCounter !== 'number') {
      throw new ProtobufValidationError('WhisperMessage missing required numeric fields')
    }

    if (
      !Number.isInteger(message.counter) ||
      !Number.isInteger(message.previousCounter) ||
      message.counter < 0 ||
      message.previousCounter < 0
    ) {
      throw new ProtobufValidationError('WhisperMessage counters must be non-negative integers')
    }
  }

  private static validatePreKey(
    message: PreKeyWhisperMessage
  ): asserts message is Required<Omit<PreKeyWhisperMessage, 'preKeyId'>> & Pick<PreKeyWhisperMessage, 'preKeyId'> {
    if (!message.identityKey || !message.baseKey || !message.message) {
      throw new ProtobufValidationError('PreKeyWhisperMessage missing required binary fields')
    }

    assertReasonableSize('PreKeyWhisperMessage.identityKey', message.identityKey, 64)
    assertReasonableSize('PreKeyWhisperMessage.baseKey', message.baseKey, 64)
    assertReasonableSize('PreKeyWhisperMessage.message', message.message, MAX_PROTO_BYTES)

    if (typeof message.signedPreKeyId !== 'number' || typeof message.registrationId !== 'number') {
      throw new ProtobufValidationError('PreKeyWhisperMessage missing required numeric fields')
    }

    if (
      !Number.isInteger(message.signedPreKeyId) ||
      !Number.isInteger(message.registrationId) ||
      message.signedPreKeyId < 0 ||
      message.registrationId < 0
    ) {
      throw new ProtobufValidationError('PreKeyWhisperMessage numeric fields must be non-negative integers')
    }
  }
}