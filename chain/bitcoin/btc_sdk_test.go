package bitcoin

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func Test_btc_create_keypair(t *testing.T) {
	t.Run("Test create_keypair", func(t *testing.T) {
		// private: fe8acc3b46815d0409154690b3e81e9237320f62d1357a163349eb734371fd4e
		// wif: L5kWPsPokqgraVeDuQt4vLmYU3H1HQXs57b39NT5n5YHZtL9ypmw
		// public: 026ae27a1995d3b2240e3b77142caf8b37c1dcec9779529931ad6924f5203f2aa9

		// P2PKH: 1CV9BT3dskAvkkkv67bSAfAgUi5spNNLTL
		// P2WPKH: bc1q0haaheusa9tem5x80e2ze7789z3h8ase8pa46f
		// P2SH-P2WPKH: 3KHuDE1Umedy9D1jiYT9uq19u5LVLysVjm
		// P2TR: bc1pdt385xv46wezgr3mwu2zetutxlqaemyh09ffjvdddyj02gpl925sll2d80

		privateKey, err := btcec.NewPrivateKey()
		if err != nil {
			panic(err)
		}
		// 获取公钥
		publicKey := privateKey.PubKey()

		// 转换为压缩格式的公钥字节
		compressedPubKey := publicKey.SerializeCompressed()

		// 计算公钥哈希
		pubKeyHash := btcutil.Hash160(compressedPubKey)

		fmt.Printf("私钥(hex): %x\n", privateKey.Serialize())
		fmt.Printf("公钥(hex): %x\n", compressedPubKey)

		// 生成不同格式的地址
		// 1. P2PKH地址 (传统地址，1开头)
		p2pkhAddr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
		if err != nil {
			panic(err)
		}

		// 2. P2WPKH地址 (原生隔离见证地址，bc1开头)
		p2wpkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
		if err != nil {
			panic(err)
		}

		// 3. P2SH-P2WPKH地址 (兼容性隔离见证地址，3开头)
		witnessProgram := btcutil.Hash160(compressedPubKey)
		witnessAddr, err := btcutil.NewAddressWitnessPubKeyHash(witnessProgram, &chaincfg.MainNetParams)
		if err != nil {
			panic(err)
		}
		script, err := txscript.PayToAddrScript(witnessAddr)
		if err != nil {
			panic(err)
		}
		p2shAddr, err := btcutil.NewAddressScriptHash(script, &chaincfg.MainNetParams)
		if err != nil {
			panic(err)
		}

		// 4. P2TR地址 (Taproot地址，bc1p开头)
		taprootPubKey := publicKey
		taprootAddr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(taprootPubKey), &chaincfg.MainNetParams)
		if err != nil {
			panic(err)
		}

		fmt.Println("\n各种格式的地址:")
		fmt.Printf("P2PKH地址: %s\n", p2pkhAddr.EncodeAddress())
		fmt.Printf("P2WPKH地址: %s\n", p2wpkhAddr.EncodeAddress())
		fmt.Printf("P2SH-P2WPKH地址: %s\n", p2shAddr.EncodeAddress())
		fmt.Printf("P2TR地址: %s\n", taprootAddr.EncodeAddress())

		// WIF格式的私钥
		wif, err := btcutil.NewWIF(privateKey, &chaincfg.MainNetParams, true)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\nWIF格式私钥: %s\n", wif.String())
	})

}

func Test_btc_wif_keypair(t *testing.T) {
	t.Run("Test wif_keypair", func(t *testing.T) {
		// 1. 首先我们有一个原始的私钥（32字节的十六进制）
		privateKey, _ := btcec.NewPrivateKey()
		privateKeyHex := hex.EncodeToString(privateKey.Serialize())
		fmt.Printf("原始私钥(hex): %s\n", privateKeyHex)

		// 2. 将私钥转换为WIF格式
		wif, _ := btcutil.NewWIF(privateKey, &chaincfg.MainNetParams, true)
		fmt.Printf("WIF格式私钥: %s\n", wif.String())

		// 3. 从WIF格式还原私钥
		decodedWIF, _ := btcutil.DecodeWIF(wif.String())
		restoredPrivKeyHex := hex.EncodeToString(decodedWIF.PrivKey.Serialize())
		fmt.Printf("从WIF还原的私钥(hex): %s\n", restoredPrivKeyHex)
	})
}
