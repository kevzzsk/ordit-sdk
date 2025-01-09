import { Psbt } from "bitcoinjs-lib"
import * as bitcoin from "bitcoinjs-lib"
import { Taptree } from "bitcoinjs-lib/src/types"
import coinSelect, { UTXO as bsUTXO } from "bitcoinselect"
import funding from "bitcoinselect/funding"
import utils from "bitcoinselect/utils"
import reverseBuffer from "buffer-reverse"

import { getAddressType } from "../addresses"
import { Chain, Network } from "../config/types"
import { buildWitnessScriptV2 } from "../inscription"
import { BaseDatasource } from "../modules"
import { decodePSBT, getNetwork, getScriptType, isP2TR, toXOnly } from "../utils"
import { OrditSDKError } from "../utils/errors"
import { processInput } from "./psbt"
import { Output, UTXO } from "./types"

interface CreateTransactionResponse {
  hex: string
  base64: string
}

interface CreateWithdrawTransactionParams {
  firstTransactionPSBTB64: string
  firstTransactionOutputIndex: number
  secondTransactionPSBTB64s: string[]
}

interface CreateSecondTransactionParams {
  firstTransactionPSBTB64: string
  outputIndex: number
  inscriptionB64String: string
}

interface GenerateInputFromPSBTOutputParams {
  psbtB64: string
  outputIndex: number
  publicKey: string
  sighashType?: number
}

interface GetBuyerCommitAddressParams {
  buyerPublicKey: string
  buyerAddress: string
  uniqueId: string
}

interface GetEscrowTaprootAddressParams {
  inscriptionOutpoint: string
  escrowPublicKey: string
  network: Network
  chain: Chain
}

interface GetEscrowTaprootAddressResponse {
  address: string
  merkleHash: string
}

interface CreateInscriptionPSBTParams {
  inscriptionId: string
  sellerPublicKey: string
  sellerAddress: string
  receivePaymentAddress: string
  inscriptionPrice: number
  escrowPublicKey: string
  datasource: BaseDatasource
  network: Network
  chain: Chain
}

interface BuildTransactionsResponse {
  firstTransactionPSBTB64: string
  secondTransactionPSBTB64s: string[]
  thirdTransactionPSBTB64: string
}

/**
 * PreInscriberWithProtection will use concept of CPFP and 3 transactions to ensure that the inscription is protected from sniping attacks.
 *
 */
export class PreInscriberWithProtection {
  private readonly network: Network
  private readonly chain: Chain
  private readonly datasource: BaseDatasource

  private readonly inscriptionsPsbts: string[] // signed inscription psbt from the seller/creator

  private readonly buyerAddress: string
  private readonly buyerPublicKey: string
  private readonly receiveAddress: string
  private buyerCommitPaymentAddress?: bitcoin.Payment
  private buyerUtxos: UTXO[] = []

  private readonly extraOutputs: Output[]

  private readonly BASE_FEERATE = 2 // feerate for other txs (except the 3rd tx)
  private readonly effectiveFeeRate: number // the average fee rate for all txs

  // escrowPublicKey is the public key of the escrow address (used to generate escrow address to hold inscription and withdraw from 3rd tx)
  private readonly escrowPublicKey: string

  // only used internally to keep track of the first tx id
  private firstTxId?: string

  constructor({
    network,
    chain,
    datasource,
    escrowPublicKey,
    inscriptionPsbts,
    buyerAddress,
    buyerPublicKey,
    receiveAddress,
    effectiveFeeRate,
    extraOutputs
  }: {
    network: Network
    chain: Chain
    datasource: BaseDatasource
    escrowPublicKey: string
    inscriptionPsbts: string[]
    buyerAddress: string
    buyerPublicKey: string
    receiveAddress: string
    effectiveFeeRate: number
    extraOutputs?: Output[]
  }) {
    this.network = network
    this.chain = chain ?? "bitcoin"
    this.datasource = datasource
    this.escrowPublicKey = escrowPublicKey

    this.inscriptionsPsbts = inscriptionPsbts
    this.buyerAddress = buyerAddress
    this.buyerPublicKey = buyerPublicKey
    this.receiveAddress = receiveAddress

    this.effectiveFeeRate = effectiveFeeRate

    this.extraOutputs = extraOutputs ?? []
  }

  private async getBuyerUtxos() {
    if (this.buyerAddress) {
      const { spendableUTXOs } = await this.datasource.getUnspents({
        address: this.buyerAddress,
        rarity: ["common", "uncommon"],
        type: "spendable",
        sort: "desc"
      })

      if (!spendableUTXOs || spendableUTXOs.length === 0) {
        throw new OrditSDKError(`No spendable utxos found for ${this.buyerAddress}`)
      }

      this.buyerUtxos = spendableUTXOs
    }
  }

  /**
   * Validate inscription psbts:
   *  - ensure each one are signed by the seller
   *  - ensure that the signed inscriptions are valid (not moved)
   * @param inscriptionB64Strings
   */
  private async validateInscriptionPsbts(inscriptionB64Strings: string[]): Promise<void> {
    const inscriptionPsbts = inscriptionB64Strings.map((b64) => decodePSBT({ base64: b64 }))

    // sanity checks
    await Promise.all(
      inscriptionPsbts.map(async (psbt) => {
        const [input] = psbt.data.inputs
        // ASSUMPTION: inscription always live on the first input
        const outpoint = `${reverseBuffer(psbt.txInputs[0].hash).toString("hex")}:${psbt.txInputs[0].index}`

        if (!input.witnessUtxo) {
          throw new OrditSDKError("invalid seller psbt")
        }
        const data = getScriptType(input.witnessUtxo.script, this.network)
        const sellerAddress = data.payload && data.payload.address ? data.payload.address : undefined
        if (!sellerAddress) {
          throw new OrditSDKError("invalid seller address in psbt")
        }

        // ensure that the inscription is not moved
        const inscriptionsRes = await this.datasource.getInscriptions({ outpoint })
        if (!inscriptionsRes || inscriptionsRes.length === 0) {
          throw new OrditSDKError(`Inscription at ${outpoint} not found`)
        }

        // ensure that the inscription is owned by the seller
        const inscriptionExists = inscriptionsRes.some(
          (inscription) => inscription.outpoint === outpoint && inscription.owner === sellerAddress
        )
        if (!inscriptionExists) {
          throw new OrditSDKError(`Inscription at ${outpoint} does not match`)
        }
      })
    )
  }

  /**
   * Build all three transaction for Buying of inscription is a safe way.
   * @param uniqueId - used to generate unique buyer commitment address -> will not be revealed on-chain
   */
  async buildTransactions({ uniqueId }: { uniqueId: string }): Promise<BuildTransactionsResponse> {
    // ensure signed inscriptionsPsbts are provided
    if (!this.inscriptionsPsbts || this.inscriptionsPsbts.length === 0) {
      throw new OrditSDKError("inscriptionsPsbts are required")
    }

    // validate buyeraddress are segwit/p2sh/taproot address
    const buyerAddressType = getAddressType(this.buyerAddress, this.network)
    if (
      buyerAddressType !== "p2sh" &&
      buyerAddressType !== "p2wsh" &&
      buyerAddressType !== "p2wpkh" &&
      buyerAddressType !== "p2tr"
    ) {
      throw new OrditSDKError(`Buyer address ${this.buyerAddress} must be a segwit/taproot/p2sh address`)
    }

    // validate inscriptionsPsbts
    await this.validateInscriptionPsbts(this.inscriptionsPsbts)

    let CPFPFunding = 600 // initial CPFP funding
    let extraCPFPFunding = CPFPFunding
    let firstTransactionPSBTB64 = ""
    let secondTransactionPSBTB64s = []
    let thirdTransactionPSBTB64 = ""

    await this.getBuyerUtxos()

    do {
      // reset second txs
      secondTransactionPSBTB64s = []

      // get buyer commitment address - where split utxos will be sent
      const buyerCommitmentAddress = this.getBuyerCommitAddress({
        buyerPublicKey: this.buyerPublicKey,
        buyerAddress: this.buyerAddress,
        uniqueId
      })

      // create 1st tx outputs to fund 2nd tx (to split all funding utxos into exact sats for 2nd txs)
      const firstTransactionOutputs: Output[] = this.inscriptionsPsbts.map((psbtB64) => {
        const psbt = decodePSBT({ base64: psbtB64 })
        const dummyAmount = 600 // insert dust value

        // add dummy input for accurate funding calculation -> this won't be used in the actual transaction
        psbt.addInput({
          hash: Buffer.alloc(32, 0),
          index: 0,
          tapInternalKey: toXOnly(Buffer.from(this.buyerPublicKey, "hex")),
          witnessUtxo: {
            script: this.buyerCommitPaymentAddress!.output!, // this is impt to ensure that input is recognized as p2tr
            value: dummyAmount // insert smallest dummy value
          },
          tapMerkleRoot: this.buyerCommitPaymentAddress!.hash!
        })

        const fundingAmount = PreInscriberWithProtection.calculateFundingAmount({
          psbtB64: psbt.toBase64(),
          feeRate: this.BASE_FEERATE
        })
        return {
          address: buyerCommitmentAddress,
          value: fundingAmount.funding + dummyAmount
        }
      })

      // add output for the 3rd tx funding - add a minimum amount for the first time (CPFPFunding will be updated with accurate estimate on subsequent loop)
      firstTransactionOutputs.push({ address: buyerCommitmentAddress, value: CPFPFunding })
      const firstTransactionOutputIndexForCPFPFunding = firstTransactionOutputs.length - 1

      // create 1st tx
      const firstTransaction = await this.createFirstTransaction(firstTransactionOutputs)
      firstTransactionPSBTB64 = firstTransaction.base64
      const firstTransactionPSBT = decodePSBT({ base64: firstTransaction.base64 })

      // create 2nd txs
      const secondTransactions = await Promise.all(
        this.inscriptionsPsbts.map(async (inscriptionB64, index) => {
          return await this.createSecondTransaction({
            firstTransactionPSBTB64: firstTransaction.base64,
            outputIndex: index,
            inscriptionB64String: inscriptionB64
          })
        })
      )
      const secondTransactionPSBTs = secondTransactions.map((tx) => decodePSBT({ base64: tx.base64 }))
      secondTransactionPSBTB64s = secondTransactions.map((tx) => tx.base64)

      // create 3rd txs
      const thirdTransaction = await this.createWithdrawTransaction({
        firstTransactionPSBTB64: firstTransaction.base64,
        firstTransactionOutputIndex: firstTransactionOutputIndexForCPFPFunding,
        secondTransactionPSBTB64s
      })
      thirdTransactionPSBTB64 = thirdTransaction.base64
      const thirdTransactionPSBT = decodePSBT({ base64: thirdTransaction.base64 })

      // --------------------------- calculate CPFP FEE ---------------------------

      // sum all vbytes of all txs
      const totalVbytes =
        this.getVBytes(firstTransactionPSBT) +
        this.getVBytes(thirdTransactionPSBT) +
        secondTransactionPSBTs.reduce((acc, psbt) => acc + this.getVBytes(psbt), 0)

      // total fee for all txs for feeRate to be at effectiveFeeRate
      const desiredTotalFee = this.effectiveFeeRate * totalVbytes
      const feesPaidByFirstTx = this.getTotalFees(firstTransactionPSBT)
      const feesPaidBySecondTxs = secondTransactionPSBTs.reduce((acc, psbt) => acc + this.getTotalFees(psbt), 0)

      // get the fee rate for 3rd tx to fund other txs (1st and 2nd txs)
      const CPFPFeeRate =
        (desiredTotalFee - (feesPaidByFirstTx + feesPaidBySecondTxs)) / this.getVBytes(thirdTransactionPSBT)

      // re-calculate 3rd tx funding with new CPFPFeeRate
      const extraFunding = PreInscriberWithProtection.calculateFundingAmount({
        psbtB64: thirdTransaction.base64,
        feeRate: CPFPFeeRate
      })

      extraCPFPFunding = extraFunding.funding
      CPFPFunding += extraCPFPFunding
    } while (extraCPFPFunding > 0)

    // all are balanced as it should be
    return { firstTransactionPSBTB64, secondTransactionPSBTB64s, thirdTransactionPSBTB64 }
  }

  /**
   * Get fees paid by psbt. Fee = Inputs - Outputs
   * @param psbt
   * @private
   */
  private getTotalFees(psbt: bitcoin.Psbt) {
    const inputs = psbt.data.inputs.reduce((acc, input) => {
      return acc + (input.witnessUtxo?.value ?? 0)
    }, 0)
    const outputs = psbt.txOutputs.reduce((acc, output) => {
      return acc + output.value
    }, 0)
    return inputs - outputs
  }

  /**
   * Get vbytes of a psbt
   * @param psbt
   * @private
   */
  private getVBytes(psbt: bitcoin.Psbt) {
    const inputs: bsUTXO[] = psbt.data.inputs.map((input, index) => {
      const txInputs = psbt.txInputs[index]
      return {
        ...input,
        value: input.witnessUtxo?.value ?? 0,
        txid: txInputs.hash,
        vout: txInputs.index,
        isTaproot: input.witnessUtxo ? !!isP2TR(input.witnessUtxo.script, this.network).payload : false
      }
    })

    return utils.transactionBytes(inputs, psbt.txOutputs)
  }

  /**
   * First transaction will be used to:
   *  - split buyer's utxos into N exact sats required for the buying of N inscription
   *  - split additional utxo to fund the 3rd CPFP transaction + extra outputs
   * Keep feerate low, will be paid by 3rd txs as CPFP.
   * Buyer will have to sign this transaction.
   */
  private async createFirstTransaction(outputs: Output[]): Promise<CreateTransactionResponse> {
    const firstTransactionPSBT = new Psbt({
      network: getNetwork(this.chain === "fractal-bitcoin" ? "mainnet" : this.network)
    })

    const inputs = await Promise.all(
      this.buyerUtxos.map(async (utxo) => {
        return {
          ...(await processInput({
            utxo,
            pubKey: this.buyerPublicKey,
            network: this.network,
            datasource: this.datasource
          })),
          txid: utxo.txid, // needed for coinselect
          vout: utxo.n, // needed for coinselect
          value: utxo.sats, // needed for coinselect,
          isTaproot: getAddressType(utxo.scriptPubKey.address, this.network) === "p2tr"
        }
      })
    )

    // pick the best buyer utxo inputs
    const res = coinSelect(inputs, outputs, this.BASE_FEERATE, this.buyerAddress)

    if (!res.inputs || res.inputs.length === 0) {
      throw new OrditSDKError("No input utxo found. Not enough funds.")
    }

    if (!res.outputs || res.outputs.length === 0) {
      throw new OrditSDKError("No output found.")
    }

    for (const input of res.inputs) {
      // we use the utxo from the buyerUtxos because coinSelect response uses uint8array and its not compatible with bitcoinjs-lib Buffer
      const utxoInput = inputs.find((i) => i.txid === input.txid && i.vout === input.vout)
      firstTransactionPSBT.addInput({
        ...utxoInput,
        hash: utxoInput!.txid,
        index: input.vout
      })
    }

    for (const _output of res.outputs) {
      if (!_output.value) {
        // sanity check for value
        throw new OrditSDKError("Output value is required")
      }
      const output = {
        address: _output.address ?? this.buyerAddress, // if no address is provided, send to buyer address -> this is normally for change output
        value: _output.value
      }
      firstTransactionPSBT.addOutput(output)
    }

    // get the txid
    const tx = bitcoin.Transaction.fromBuffer(firstTransactionPSBT.data.getTransaction())
    for (let i = 0; i < res.inputs.length; i++) {
      const input = res.inputs[i]
      if (input.redeemScript) {
        // for p2sh inputs, need to include the redeem script as this changes the txid hash
        tx.setInputScript(i, bitcoin.script.compile([Buffer.from(input.redeemScript)]))
      }
    }
    this.firstTxId = tx.getId()

    return {
      hex: firstTransactionPSBT.toHex(),
      base64: firstTransactionPSBT.toBase64()
    }
  }

  /**
   * Second transaction will be used to:
   *  - send inscription into the inscription holding address
   *  - send funds to the seller address
   *  Buyer will have to sign this transaction (SIGHASH_ALL)
   *  Seller will have to sign this transaction (SIGHASH_ALL | SIGHASH_ANYONECANPAY)
   */
  private async createSecondTransaction({
    firstTransactionPSBTB64,
    outputIndex,
    inscriptionB64String
  }: CreateSecondTransactionParams): Promise<CreateTransactionResponse> {
    const inscriptionPsbt = decodePSBT({ base64: inscriptionB64String })

    const input = {
      ...this.generateInputFromPSBTOutput({
        psbtB64: firstTransactionPSBTB64,
        outputIndex,
        publicKey: this.buyerPublicKey,
        sighashType: bitcoin.Transaction.SIGHASH_ALL
      }),
      hash: this.firstTxId!,
      tapMerkleRoot: this.buyerCommitPaymentAddress!.hash!
    }
    inscriptionPsbt.addInput(input)

    return {
      hex: inscriptionPsbt.toHex(),
      base64: inscriptionPsbt.toBase64()
    }
  }

  /**
   * 3rd transaction will be used to:
   *  - send inscription from the inscription holding address to the buyer address
   *  - CPFP the 2nd and 1st txs
   *  - pay for extra outputs
   */
  private async createWithdrawTransaction({
    firstTransactionPSBTB64,
    firstTransactionOutputIndex,
    secondTransactionPSBTB64s
  }: CreateWithdrawTransactionParams): Promise<CreateTransactionResponse> {
    // create all the inputs from the output of 2nd txs
    const inputs = secondTransactionPSBTB64s.map((psbtB64) => {
      const outputIndex = 0
      const psbt = decodePSBT({ base64: psbtB64 })
      const inscriptionOutpoint = `${reverseBuffer(psbt.txInputs[outputIndex].hash).toString("hex")}:${psbt.txInputs[outputIndex].index}`

      const { merkleHash } = PreInscriberWithProtection.getEscrowTaprootAddress({
        inscriptionOutpoint,
        escrowPublicKey: this.escrowPublicKey,
        network: this.network,
        chain: this.chain
      })
      return {
        ...this.generateInputFromPSBTOutput({
          psbtB64,
          outputIndex,
          publicKey: this.escrowPublicKey,
          sighashType: bitcoin.Transaction.SIGHASH_ALL
        }),
        tapMerkleRoot: Buffer.from(merkleHash, "hex")
      }
    })

    const withdrawTransactionPSBT = new Psbt({
      network: getNetwork(this.chain === "fractal-bitcoin" ? "mainnet" : this.network)
    })

    // add input and corresponding output to send inscription to receiver address
    for (const input of inputs) {
      withdrawTransactionPSBT.addInput(input)
      withdrawTransactionPSBT.addOutput({ address: this.receiveAddress, value: input.witnessUtxo.value })
    }
    // add extra outputs - if any
    for (const output of this.extraOutputs) {
      withdrawTransactionPSBT.addOutput(output)
    }

    // add funding input
    const fundingInput = this.generateInputFromPSBTOutput({
      psbtB64: firstTransactionPSBTB64,
      outputIndex: firstTransactionOutputIndex,
      publicKey: this.buyerPublicKey,
      sighashType: bitcoin.Transaction.SIGHASH_ALL
    })

    withdrawTransactionPSBT.addInput({
      ...fundingInput,
      hash: this.firstTxId!,
      tapMerkleRoot: Buffer.from(this.buyerCommitPaymentAddress!.hash!.toString("hex"), "hex")
    })

    return {
      hex: withdrawTransactionPSBT.toHex(),
      base64: withdrawTransactionPSBT.toBase64()
    }
  }

  /**
   * Generate input from PSBT output - used to create inputs for the next chained transaction
   * @param psbtB64
   * @param outputIndex
   * @param publicKey
   * @param sighashType
   * @private
   */
  private generateInputFromPSBTOutput({
    psbtB64,
    outputIndex,
    publicKey,
    sighashType
  }: GenerateInputFromPSBTOutputParams) {
    const psbt = decodePSBT({ base64: psbtB64 })
    const tx = bitcoin.Transaction.fromBuffer(psbt.data.getTransaction())

    const psbtOutput = psbt.txOutputs[outputIndex]

    const scriptType = getScriptType(psbtOutput.script, this.network)

    switch (scriptType.type) {
      case "p2tr":
        return {
          hash: tx.getId(),
          index: outputIndex,
          tapInternalKey: toXOnly(Buffer.from(publicKey, "hex")),
          witnessUtxo: {
            script: psbtOutput.script,
            value: psbtOutput.value
          },
          ...(sighashType ? { sighashType } : undefined)
        }
      case "p2wpkh":
        return {
          hash: tx.getId(),
          index: outputIndex,
          witnessUtxo: {
            script: psbt.txOutputs[outputIndex].script,
            value: psbt.txOutputs[outputIndex].value
          },
          ...(sighashType ? { sighashType } : undefined)
        }

      default:
        throw new OrditSDKError("scripts other than p2tr and p2wpkh are not supported!")
    }
  }

  private getBuyerCommitAddress({ buyerPublicKey, buyerAddress, uniqueId }: GetBuyerCommitAddressParams): string {
    const buyerXPub = toXOnly(Buffer.from(buyerPublicKey, "hex")).toString("hex")

    const mediaContent = {
      buyerPublicKey,
      buyerAddress,
      uniqueId
    }

    const dataScript = buildWitnessScriptV2({
      xkey: buyerXPub,
      envelopes: [
        {
          mediaContent: JSON.stringify(mediaContent),
          mediaType: "application/json;charset=utf-8",
          receiverAddress: buyerAddress,
          postage: 0
        }
      ]
    })

    const redeemScript = bitcoin.script.compile([Buffer.from(buyerXPub, "hex"), bitcoin.opcodes.OP_CHECKSIG])

    const taprootTree: Taptree = [{ output: redeemScript }, { output: dataScript }]
    const payment = bitcoin.payments.p2tr({
      internalPubkey: Buffer.from(buyerXPub, "hex"),
      network: getNetwork(this.chain === "fractal-bitcoin" ? "mainnet" : this.network),
      scriptTree: taprootTree
    })

    if (!payment.address) {
      throw new OrditSDKError("Error while creating escrow address")
    }

    // TODO: refactor this side-effect ?
    this.buyerCommitPaymentAddress = payment

    return payment.address
  }

  static getEscrowTaprootAddress({
    inscriptionOutpoint,
    escrowPublicKey,
    network,
    chain
  }: GetEscrowTaprootAddressParams): GetEscrowTaprootAddressResponse {
    const escrowXPub = toXOnly(Buffer.from(escrowPublicKey, "hex")).toString("hex")

    const mediaContent = {
      inscriptionOutpoint
    }

    const dataScript = buildWitnessScriptV2({
      xkey: escrowXPub,
      envelopes: [
        {
          mediaContent: JSON.stringify(mediaContent),
          mediaType: "application/json;charset=utf-8",
          receiverAddress: "",
          postage: 0
        }
      ]
    })

    const redeemScript = bitcoin.script.compile([Buffer.from(escrowXPub, "hex"), bitcoin.opcodes.OP_CHECKSIG])

    const taprootTree: Taptree = [{ output: redeemScript }, { output: dataScript }]
    const payment = bitcoin.payments.p2tr({
      internalPubkey: Buffer.from(escrowXPub, "hex"),
      network: getNetwork(chain === "fractal-bitcoin" ? "mainnet" : network),
      scriptTree: taprootTree
    })

    if (!payment.address || !payment.hash) {
      throw new OrditSDKError("Error while creating escrow address")
    }

    return {
      address: payment.address,
      merkleHash: payment.hash.toString("hex")
    }
  }

  static async createInscriptionPSBT({
    inscriptionId,
    sellerPublicKey,
    sellerAddress,
    receivePaymentAddress,
    inscriptionPrice,
    escrowPublicKey,
    datasource,
    network,
    chain
  }: CreateInscriptionPSBTParams): Promise<CreateTransactionResponse> {
    const inscriptionUtxo = await datasource.getInscriptionUTXO({
      id: inscriptionId
    })

    // validate inscriptionUtxo
    if (!inscriptionUtxo) {
      throw new OrditSDKError(`Inscription ${inscriptionId} not found`)
    }
    if (inscriptionUtxo.scriptPubKey.address !== sellerAddress) {
      throw new OrditSDKError(`Inscription ${inscriptionId} does not belong to seller`)
    }

    const inscriptionOutpoint = `${inscriptionUtxo.txid}:${inscriptionUtxo.n}`

    const input = await processInput({
      utxo: inscriptionUtxo,
      pubKey: sellerPublicKey,
      network: network,
      sighashType: bitcoin.Transaction.SIGHASH_ALL | bitcoin.Transaction.SIGHASH_ANYONECANPAY,
      datasource: datasource
    })

    const outputs = [
      {
        address: this.getEscrowTaprootAddress({
          inscriptionOutpoint,
          escrowPublicKey,
          network,
          chain
        }).address,
        value: inscriptionUtxo.sats
      }, // send inscription to escrow
      { address: receivePaymentAddress, value: inscriptionPrice } // send payment to seller address
    ]

    const psbt = new Psbt({ network: getNetwork(chain === "fractal-bitcoin" ? "mainnet" : network) })
    psbt.addInput(input)
    psbt.addOutputs(outputs)

    return {
      hex: psbt.toHex(),
      base64: psbt.toBase64()
    }
  }

  /**
   * Calculate the funding sats needed for the given PSBT.
   * Additional weight/size from adding another input will not be considered in this calculation.
   * Hence, it is important to inject a funding input with minimum sats to ensure that the funding is accurate.
   * @param psbtB64 - can be a signed/unsigned psbt
   * @param feeRate
   */
  static calculateFundingAmount({ psbtB64, feeRate }: { psbtB64: string; feeRate: number }) {
    const psbt = decodePSBT({ base64: psbtB64 })

    const inputs = psbt.txInputs.map((txInput, index) => {
      const inputData = psbt.data.inputs[index]

      return {
        ...inputData,
        txid: reverseBuffer(txInput.hash).toString("hex"),
        vout: txInput.index,
        value: inputData.witnessUtxo?.value ?? 0,
        isTaproot: inputData.witnessUtxo ? !!isP2TR(inputData.witnessUtxo.script, "mainnet").payload : false // for the purpose of checking p2tr, networks don't matter
      }
    })

    const res = funding(inputs, psbt.txOutputs, feeRate)

    return {
      funding: res.funding
    }
  }
}
