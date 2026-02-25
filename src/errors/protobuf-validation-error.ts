export class ProtobufValidationError extends Error {
  readonly name = 'ProtobufValidationError'

  constructor(message: string) {
    super(message)
  }
}
