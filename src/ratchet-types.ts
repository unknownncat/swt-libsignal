/**
 * Define o tipo da cadeia no Double Ratchet.
 * - SENDING: cadeia usada para enviar mensagens
 * - RECEIVING: cadeia usada para receber mensagens
 */
export const ChainType = {
    SENDING: 1,
    RECEIVING: 2
} as const;

export type ChainType = typeof ChainType[keyof typeof ChainType];

/**
 * Define a origem da chave base.
 * - OURS: chave gerada localmente
 * - THEIRS: chave recebida do peer
 */
export const BaseKeyType = {
    OURS: 1,
    THEIRS: 2
} as const;

export type BaseKeyType = typeof BaseKeyType[keyof typeof BaseKeyType];
