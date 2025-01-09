import { JsonRpcDatasource } from "@sadoprotocol/ordit-sdk"
import { Ordit } from "@sadoprotocol/ordit-sdk"
import { bulkMintFromCollection } from "@sadoprotocol/ordit-sdk"
import { PreInscriberWithProtection } from "@sadoprotocol/ordit-sdk"
import * as bitcoin from "bitcoinjs-lib"

const MNEMONIC = "<mnemonic>"
const MNEMONIC_SELLER = "<mnemonic>"
const MNEMONIC_BUYER = "<mnemonic>"
const network = "regtest"
const chain = "bitcoin"
const datasource = new JsonRpcDatasource({ network })

// init wallet
const escrowWallet = new Ordit({
  bip39: MNEMONIC,
  chain,
  network
})
escrowWallet.setDefaultAddress("taproot")

const sellerWallet = new Ordit({
  bip39: MNEMONIC_SELLER,
  network,
  chain
})
sellerWallet.setDefaultAddress("segwit", { addressIndex: 0, accountIndex: 0 })

const buyerWallet = new Ordit({
  bip39: MNEMONIC_BUYER,
  network,
  chain
})
buyerWallet.setDefaultAddress("taproot", { addressIndex: 0, accountIndex: 3 })
const buyerWalletTaprootAddress = buyerWallet.selectedAddress
buyerWallet.setDefaultAddress("nested-segwit", { addressIndex: 0, accountIndex: 3 })

// image/png
const pngImage =
  "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAMAAACdt4HsAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAABVQTFRFJCQk3NjMAAAAqJiWbmNjMjExDw4Op1iMBgAAAXNJREFUeNrslwuShCAMROkhev8jjyThjxiL2XVrayKloubRhIDqXovm/iJgdzPjRwioABDzEUBE7tjCTvcFgPTpEUAOcwCS1QB/H4AS4L0vAEPbd74BLnxABvhgpQJpu2pc0YgbSoBBQbzFTV8CKFsPMCgoQpg60ShoYtAOo/rSCNAMwxAw7YIJMAuiBUDUS/hdBSnZ1NcCqOaCjJIOttTuKYBDkTFanQPqROKGG8BgNp4p8ClhU9Zmf38aA18TTqzy74IImdYzA2YxuG29ggUAFgHrXWAjow0BIZGc0egsE1cALGIB8C+6gMe7EAGQZaxcDm8pgPrFZSwti7Ears9ikACoPgVcWqFwkQdZQfasAJdB1BjEd0HfhW8q/1gqy8v1UQVfwBCADVuYABufh5kQqzYAXzoYXA63LZxx9ZYCLlmLlB7AK8GJggBQLS4BxGEOkHZVvcRAO2METEehBXxqGK3WAV75n9T6w5scnv/5fgswAO3WEmd/piDfAAAAAElFTkSuQmCC"
const ordzaarPassType = "image/png"

// used for minting initial inscriptions
async function inscribeBulk() {
  // map and create 20 inscriptions
  const inscriptionsToMint = new Array(100).fill(0).map((_, i) => ({
    mediaContent: pngImage,
    mediaType: ordzaarPassType,
    postage: 600,
    nonce: i,
    receiverAddress: sellerWallet.selectedAddress,
    iid: i.toString()
  }))

  // new inscription tx
  const transaction = await bulkMintFromCollection({
    address: escrowWallet.selectedAddress,
    publicKey: escrowWallet.publicKey,
    publisherAddress: escrowWallet.selectedAddress,
    collectionGenesis: "df91a6386fb9b55bd754d6ec49e97e1be4c80ac49e4242ff773634e4c23cc427",
    changeAddress: sellerWallet.selectedAddress,
    feeRate: 10,
    outputs: [],
    network,
    datasource,
    taptreeVersion: "3",
    inscriptions: inscriptionsToMint
  })

  // generate deposit address and fee for inscription
  const revealed = await transaction.generateCommit()
  console.log(revealed) // deposit revealFee to address

  // confirm if deposit address has been funded
  const ready = await transaction.isReady()

  if (ready || transaction.ready) {
    // build transaction
    await transaction.build()

    // sign transaction
    const signedTxHex = escrowWallet.signPsbt(transaction.toHex(), { isRevealTx: true })

    // Broadcast transaction
    const tx = await datasource.relay({ hex: signedTxHex })
    console.log(tx)
  }
}

/**
 * for using PreInscriberWithProtection
 */
async function preinscriberWithProtection() {
  // ------------------  Seller Signs Inscriptions  ------------------

  const inscriptionIds = [
    "dec9881438b8c30423fe6e81ef008a328e2393f53d23873aac5b824acd701edci16",
    "dec9881438b8c30423fe6e81ef008a328e2393f53d23873aac5b824acd701edci17"
  ]

  const inscriptionPsbts = await Promise.all(
    inscriptionIds.map(async (id) => {
      return await PreInscriberWithProtection.createInscriptionPSBT({
        inscriptionId: id,
        sellerPublicKey: sellerWallet.publicKey,
        sellerAddress: sellerWallet.selectedAddress,
        receivePaymentAddress: sellerWallet.selectedAddress,
        inscriptionPrice: 1000,
        escrowPublicKey: escrowWallet.publicKey,
        datasource,
        network,
        chain
      })
    })
  )

  const inscriptionPsbtsB64 = inscriptionPsbts.map((psbt) => psbt.base64)
  const signedInscriptionPsbts = []
  // signs all psbts
  for (const psbtB64 of inscriptionPsbtsB64) {
    const signedPsbt = await sellerWallet.signPsbt(psbtB64, { finalize: false, extractTx: false, isRevealTx: true })
    // convert hex to b64
    const base64Psbt = bitcoin.Psbt.fromHex(signedPsbt).toBase64()
    signedInscriptionPsbts.push(base64Psbt)
  }

  // ------------------  Buyer + Escrow Signs Transactions  ------------------

  // init preinscriber with protection when buyer is ready to buy
  const preinscriber = new PreInscriberWithProtection({
    network,
    chain,
    datasource,
    inscriptionPsbts: signedInscriptionPsbts, // pass in the seller signed psbts
    escrowPublicKey: escrowWallet.publicKey,
    buyerAddress: buyerWallet.selectedAddress,
    buyerPublicKey: buyerWallet.publicKey,
    receiveAddress: buyerWalletTaprootAddress,
    effectiveFeeRate: 8
  })
  // build the transactions
  const psbts = await preinscriber.buildTransactions({ uniqueId: "uniqueId" })
  // buyer signs all transactions
  const firstTxSigned = await buyerWallet.signPsbt(psbts.firstTransactionPSBTB64, {
    finalize: true,
    extractTx: true,
    isRevealTx: true
  })
  const secondTxsSigned = await Promise.all(
    psbts.secondTransactionPSBTB64s.map(async (psbt) => {
      return buyerWallet.signPsbt(psbt, {
        finalize: true,
        extractTx: true,
        isRevealTx: false,
        indexesToSign: [1]
      })
    })
  )
  const thirdTxBuyerSigned = await buyerWallet.signPsbt(psbts.thirdTransactionPSBTB64, {
    finalize: false,
    extractTx: false,
    isRevealTx: false,
    indexesToSign: [psbts.secondTransactionPSBTB64s.length]
  })

  // server signs third tx
  const thirdTxServerSigned = await escrowWallet.signPsbt(thirdTxBuyerSigned, {
    finalize: true,
    extractTx: true,
    isRevealTx: false,
    indexesToSign: psbts.secondTransactionPSBTB64s.map((_, i) => i)
  })

  console.log(JSON.stringify([firstTxSigned, ...secondTxsSigned, thirdTxServerSigned]))
}

preinscriberWithProtection()
