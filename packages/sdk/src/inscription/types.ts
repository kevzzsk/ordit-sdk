export enum RarityEnum {
    COMMON = "common",
    UNCOMMON = "uncommon",
    RARE = "rare",
    EPIC = "epic",
    LEGENDARY = "legendary",
    MYTHIC = "mythic",
}

export type Rarity = `${RarityEnum}`

export interface Ordinal {
  number: number;
  decimal: string;
  degree: string;
  name: string;
  height: number;
  cycle: number;
  epoch: number;
  period: number;
  offset: number;
  rarity: Rarity;
  output: string;
  start: number;
  size: number;
}

export interface Inscription {
  id: string;
  outpoint: string;
  owner: string;
  fee: number;
  height: number;
  number: number;
  sat: number;
  timestamp: number;
  mediaType: string;
  mediaSize: number;
  mediaContent: string;
  meta?: Record<string, any>;
}