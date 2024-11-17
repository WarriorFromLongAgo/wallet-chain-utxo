package bitcoin

import (
	"fmt"
	common2 "github.com/dapplink-labs/wallet-chain-utxo/rpc/common"
	"github.com/dapplink-labs/wallet-chain-utxo/rpc/utxo"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func Test_btc_ConvertAddress(t *testing.T) {
	adaptor := &ChainAdaptor{}

	// private: fe8acc3b46815d0409154690b3e81e9237320f62d1357a163349eb734371fd4e
	// wif private: L5kWPsPokqgraVeDuQt4vLmYU3H1HQXs57b39NT5n5YHZtL9ypmw

	// public: 026ae27a1995d3b2240e3b77142caf8b37c1dcec9779529931ad6924f5203f2aa9

	// P2PKH: 1CV9BT3dskAvkkkv67bSAfAgUi5spNNLTL
	// P2WPKH: bc1q0haaheusa9tem5x80e2ze7789z3h8ase8pa46f
	// P2SH-P2WPKH: 3KHuDE1Umedy9D1jiYT9uq19u5LVLysVjm
	// P2TR: bc1pdt385xv46wezgr3mwu2zetutxlqaemyh09ffjvdddyj02gpl925sll2d80

	pubKeyHex := "026ae27a1995d3b2240e3b77142caf8b37c1dcec9779529931ad6924f5203f2aa9"
	fmt.Printf("Public Key: %s\n", pubKeyHex)

	t.Run("Test P2PKH address", func(t *testing.T) {
		req := &utxo.ConvertAddressRequest{
			Chain:     ChainName,
			Network:   "MAINNET",
			Format:    AddressFormatP2PKH,
			PublicKey: pubKeyHex,
		}

		resp, err := adaptor.ConvertAddress(req)
		require.NoError(t, err)
		require.Equal(t, common2.ReturnCode_SUCCESS, resp.Code)
		require.True(t, strings.HasPrefix(resp.Address, "1"))
		fmt.Printf("P2PKH Address: %s\n", resp.Address)
	})

	t.Run("Test P2WPKH address", func(t *testing.T) {
		req := &utxo.ConvertAddressRequest{
			Chain:     ChainName,
			Network:   "MAINNET",
			Format:    AddressFormatP2WPKH,
			PublicKey: pubKeyHex,
		}

		resp, err := adaptor.ConvertAddress(req)
		require.NoError(t, err)
		require.Equal(t, common2.ReturnCode_SUCCESS, resp.Code)
		require.True(t, strings.HasPrefix(resp.Address, "bc1q"))
		fmt.Printf("P2WPKH Address: %s\n", resp.Address)
	})

	t.Run("Test P2SH address", func(t *testing.T) {
		req := &utxo.ConvertAddressRequest{
			Chain:     ChainName,
			Network:   "MAINNET",
			Format:    AddressFormatP2SH,
			PublicKey: pubKeyHex,
		}

		resp, err := adaptor.ConvertAddress(req)
		require.NoError(t, err)
		require.Equal(t, common2.ReturnCode_SUCCESS, resp.Code)
		require.True(t, strings.HasPrefix(resp.Address, "3"))
		fmt.Printf("P2SH Address: %s\n", resp.Address)
	})

	t.Run("Test P2TR address", func(t *testing.T) {
		req := &utxo.ConvertAddressRequest{
			Chain:     ChainName,
			Network:   "MAINNET",
			Format:    AddressFormatP2TR,
			PublicKey: pubKeyHex,
		}

		resp, err := adaptor.ConvertAddress(req)
		require.NoError(t, err)
		require.Equal(t, common2.ReturnCode_SUCCESS, resp.Code)
		require.True(t, strings.HasPrefix(resp.Address, "bc1p"))
		fmt.Printf("P2TR Address: %s\n", resp.Address)
	})
}

func Test_btc_ValidAddress(t *testing.T) {
	chainAdaptor := &ChainAdaptor{}

	t.Run("测试有效的比特币地址", func(t *testing.T) {
		request := &utxo.ValidAddressRequest{
			Chain:   ChainName,
			Network: "mainnet",
			Address: "1CV9BT3dskAvkkkv67bSAfAgUi5spNNLTL",
		}

		response, err := chainAdaptor.ValidAddress(request)

		if err != nil {
			t.Errorf("验证有效地址时发生错误: %v", err)
		}
		if !response.Valid {
			t.Error("应该验证为有效地址")
		}
		if response.Code != common2.ReturnCode_SUCCESS {
			t.Error("应该返回成功状态码")
		}
	})

	// 测试用例2：验证无效的比特币地址
	t.Run("测试无效的比特币地址", func(t *testing.T) {
		request := &utxo.ValidAddressRequest{
			Chain:   ChainName,
			Network: "mainnet",
			Address: "invalid_address",
		}

		response, err := chainAdaptor.ValidAddress(request)
		require.Error(t, err)
		require.Nil(t, response)
	})

}
