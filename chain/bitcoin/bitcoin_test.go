package bitcoin

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/dapplink-labs/wallet-chain-utxo/config"
	"github.com/ethereum/go-ethereum/log"
	"github.com/pkg/errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	common2 "github.com/dapplink-labs/wallet-chain-utxo/rpc/common"
	"github.com/dapplink-labs/wallet-chain-utxo/rpc/utxo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupChainAdaptor(t *testing.T) *ChainAdaptor {
	const (
		baseURL     = "127.0.0.1:18556"
		rpcUser     = "jamie"
		rpcPassword = "123456"
	)
	conf := &config.Config{
		WalletNode: config.WalletNode{
			Btc: config.Node{
				RpcUrl:     baseURL,                 // 测试环境RPC地址
				RpcUser:    rpcUser,                 // 测试用户名
				RpcPass:    rpcPassword,             // 测试密码
				DataApiUrl: "http://localhost:8333", // 测试数据API地址
				DataApiKey: "test_api_key",          // 测试API密钥
				TpApiUrl:   "http://localhost:8334", // 第三方API地址
			},
		},
	}

	// 创建 ChainAdaptor
	adaptor, err := NewChainAdaptor(conf)
	require.NoError(t, err, "创建ChainAdaptor失败")
	require.NotNil(t, adaptor, "ChainAdaptor不能为空")

	// 类型断言
	chainAdaptor, ok := adaptor.(*ChainAdaptor)
	require.True(t, ok, "类型断言失败")
	require.NotNil(t, chainAdaptor.btcClient, "btcClient不能为空")
	require.NotNil(t, chainAdaptor.btcdClient, "btcdClient不能为空")
	require.NotNil(t, chainAdaptor.btcDataClient, "btcDataClient不能为空")
	require.NotNil(t, chainAdaptor.thirdPartClient, "thirdPartClient不能为空")

	return chainAdaptor
}

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

func TestChainAdaptor_CreateUnSignTransaction(t *testing.T) {
	adaptor := setupChainAdaptor(t)

	t.Run("测试创建未签名交易", func(t *testing.T) {
		totalAmount := int64(5000000000)             // 50 BTC
		feeAmount := int64(10000)                    // 0.0001 BTC
		amount1 := int64(3000000000)                 // 30 BTC
		amount2 := totalAmount - amount1 - feeAmount // 19.9999 BTC

		req := &utxo.UnSignTransactionRequest{
			ConsumerToken: "test_token",
			Chain:         ChainName,
			Network:       "simnet",
			Fee:           strconv.FormatInt(feeAmount, 10),
			Vin: []*utxo.Vin{
				{
					Hash:    "19649fa3ed520226dac289c2db8d8b00c27b934835935cf3b2b4e1f0fde53f44", // coinbase 交易ID
					Index:   0,                                                                  // 第一个输出
					Amount:  totalAmount,                                                        // 50 BTC
					Address: "Sh9MkzRkKu7vhUUysk9xxvR5e2KgpyjRMV",                               // coinbase 输出地址
				},
			},
			// 两个不同类型的输出地址
			Vout: []*utxo.Vout{
				{
					Address: "sb1q5hfl9hwlkkqtldwfywuhkksev8ecc8gy5w650w", // SegWit地址
					Amount:  amount1,                                      // 30 BTC
					Index:   0,
				},
				{
					Address: "Sh9MkzRkKu7vhUUysk9xxvR5e2KgpyjRMV", // 传统地址
					Amount:  amount2,                              // 19.9999 BTC
					Index:   1,
				},
			},
		}

		resp, err := adaptor.CreateUnSignTransaction(req)
		if err != nil {
			t.Logf("创建交易失败: %v", err)
		} else {
			t.Logf("创建交易成功")
		}
		// 1. 检查错误
		require.NoError(t, err, "创建未签名交易不应该返回错误")
		require.NotNil(t, resp, "响应不应该为空")

		// 2. 检查返回码
		assert.Equal(t, common2.ReturnCode_SUCCESS, resp.Code, "返回码应该是成功")

		// 3. 检查交易数据
		assert.NotEmpty(t, resp.TxData, "交易数据不应该为空")

		// 4. 检查签名哈希
		assert.Equal(t, len(req.Vin), len(resp.SignHashes), "签名哈希数量应该与输入数量相同")

		// 5. 检查每个签名哈希的长度（应该是32字节）
		for _, hash := range resp.SignHashes {
			assert.Equal(t, 32, len(hash), "签名哈希长度应该是32字节")
		}

		// 6. 验证交易数据格式
		var tx wire.MsgTx
		if err = tx.Deserialize(bytes.NewReader(resp.TxData)); err == nil {
			t.Logf("\n=== 交易详情 ===")
			t.Logf("版本号: %d", tx.Version)

			t.Logf("\n输入详情:")
			for i, in := range tx.TxIn {
				t.Logf("输入[%d]:", i)
				t.Logf("- 前置交易哈希: %s", in.PreviousOutPoint.Hash)
				t.Logf("- 输出索引: %d", in.PreviousOutPoint.Index)
				t.Logf("- 签名脚本长度: %d", len(in.SignatureScript))
				t.Logf("- 序列号: %d", in.Sequence)
			}

			t.Logf("\n输出详情:")
			for i, out := range tx.TxOut {
				t.Logf("输出[%d]:", i)
				t.Logf("- 金额: %f BTC (%d satoshi)", float64(out.Value)/1e8, out.Value)
				t.Logf("- 锁定脚本长度: %d", len(out.PkScript))
				t.Logf("- 锁定脚本(hex): %x", out.PkScript)
			}

			t.Logf("\n交易总览:")
			totalIn := totalAmount
			totalOut := int64(0)
			for _, out := range tx.TxOut {
				totalOut += out.Value
			}
			t.Logf("总输入: %f BTC", float64(totalIn)/1e8)
			t.Logf("总输出: %f BTC", float64(totalOut)/1e8)
			t.Logf("手续费: %f BTC", float64(totalIn-totalOut)/1e8)
		} else {
			t.Logf("\n反序列化交易失败: %v", err)
		}

		// 7. 验证交易结构
		assert.Equal(t, len(req.Vin), len(tx.TxIn), "交易输入数量应该匹配")
		assert.Equal(t, len(req.Vout), len(tx.TxOut), "交易输出数量应该匹配")

		// 8. 验证输出金额
		assert.Equal(t, req.Vout[0].Amount, tx.TxOut[0].Value, "输出金额应该匹配")
	})
}

func TestChainAdaptor_BuildSignedTransaction(t *testing.T) {
	adaptor := setupChainAdaptor(t)

	totalAmount := int64(5000000000)             // 50 BTC
	feeAmount := int64(10000)                    // 0.0001 BTC
	amount1 := int64(3000000000)                 // 30 BTC
	amount2 := totalAmount - amount1 - feeAmount // 19.9999 BTC

	t.Run("测试构建已签名交易", func(t *testing.T) {
		// 1. 首先创建一个未签名交易
		unsignedReq := &utxo.UnSignTransactionRequest{
			ConsumerToken: "test_token",
			Chain:         ChainName,
			Network:       "simnet",
			Fee:           strconv.FormatInt(feeAmount, 10),
			// 使用 coinbase 交易作为输入
			Vin: []*utxo.Vin{
				{
					Hash:    "19649fa3ed520226dac289c2db8d8b00c27b934835935cf3b2b4e1f0fde53f44",
					Index:   0,
					Amount:  totalAmount,
					Address: "Sh9MkzRkKu7vhUUysk9xxvR5e2KgpyjRMV",
				},
			},
			Vout: []*utxo.Vout{
				{
					Address: "sb1q5hfl9hwlkkqtldwfywuhkksev8ecc8gy5w650w", // SegWit地址
					Amount:  amount1,
					Index:   0,
				},
				{
					Address: "Sh9MkzRkKu7vhUUysk9xxvR5e2KgpyjRMV", // 传统地址
					Amount:  amount2,
					Index:   1,
				},
			},
		}

		// 2. 获取未签名交易数据
		unsignedResp, err := adaptor.CreateUnSignTransaction(unsignedReq)
		require.NoError(t, err, "创建未签名交易失败")
		require.NotNil(t, unsignedResp, "未签名交易响应不能为空")

		// 3. 准备签名数据（这里使用模拟数据）
		wif := "FtzAeaXBzedBN7WPwWaXM9hyxVm7daEV2mv1oQGFNN3CACEbNm7H"
		decodedWIF, err := btcutil.DecodeWIF(wif)
		require.NoError(t, err, "解码WIF私钥失败")
		privKey := decodedWIF.PrivKey
		t.Logf("使用私钥地址: %s", "Sh9MkzRkKu7vhUUysk9xxvR5e2KgpyjRMV")
		t.Logf("私钥(WIF): %s", wif)

		// 4. 对每个输入进行签名
		signatures := make([][]byte, len(unsignedReq.Vin))
		publicKeys := make([][]byte, len(unsignedReq.Vin))

		for i, hash := range unsignedResp.SignHashes {
			// 使用私钥签名
			signature := ecdsa.Sign(privKey, hash) // 直接获取签名，不需要处理error
			// 序列化签名
			sigBytes := signature.Serialize()
			signatures[i] = append(sigBytes, byte(txscript.SigHashAll))
			// 获取公钥
			publicKeys[i] = privKey.PubKey().SerializeCompressed()
			t.Logf("Signature %d length: %d", i, len(signatures[i]))
			t.Logf("Signature %d: %x", i, signatures[i])
			t.Logf("Public key %d: %x", i, publicKeys[i])
		}

		// 5. 构建签名请求
		signedReq := &utxo.SignedTransactionRequest{
			ConsumerToken: "test_token",
			Chain:         ChainName,
			Network:       "simnet",
			TxData:        unsignedResp.TxData,
			Signatures:    signatures,
			PublicKeys:    publicKeys,
		}

		// 6. 调用被测试的方法
		signedResp, err := adaptor.BuildSignedTransaction(signedReq)
		t.Logf("\nBuildSignedTransaction failed:")
		t.Logf("Error: %v", err)
		// 7. 验证结果
		require.NoError(t, err, "构建已签名交易失败")
		require.NotNil(t, signedResp, "已签名交易响应不能为空")

		signedRespJson, err := json.Marshal(signedResp)
		require.NoError(t, err, "signedResp json fail")
		t.Logf("BuildSignedTransaction signedResp: %s", string(signedRespJson))

		// 8. 打印详细信息
		t.Logf("\n=== 已签名交易响应 ===")
		t.Logf("响应码: %v", signedResp.Code)
		t.Logf("响应消息: %s", signedResp.Msg)
		t.Logf("交易哈希: %x", signedResp.Hash)
		t.Logf("已签名交易数据长度: %d bytes", len(signedResp.SignedTxData))
		t.Logf("已签名交易数据(hex): %x", signedResp.SignedTxData)

		// 9. 验证交易结构
		var signedTx wire.MsgTx
		err = signedTx.Deserialize(bytes.NewReader(signedResp.SignedTxData))
		require.NoError(t, err, "反序列化已签名交易失败")

		signedTxJson, err := json.Marshal(signedTx)
		require.NoError(t, err, "signedTxJson json fail")
		t.Logf("BuildSignedTransaction signedTxJson: %s", string(signedTxJson))

		// 10. 打印交易详情
		t.Logf("\n=== 交易详情 ===")
		t.Logf("版本号: %d", signedTx.Version)
		t.Logf("输入数量: %d", len(signedTx.TxIn))
		for i, in := range signedTx.TxIn {
			t.Logf("输入[%d]:", i)
			t.Logf("- 前置交易: %s", in.PreviousOutPoint.Hash)
			t.Logf("- 输出索引: %d", in.PreviousOutPoint.Index)
			t.Logf("- 签名脚本长度: %d", len(in.SignatureScript))
			t.Logf("- 签名脚本(hex): %x", in.SignatureScript)
		}

		t.Logf("输出数量: %d", len(signedTx.TxOut))
		for i, out := range signedTx.TxOut {
			t.Logf("输出[%d]:", i)
			t.Logf("- 金额: %f BTC", float64(out.Value)/1e8)
			t.Logf("- 锁定脚本长度: %d", len(out.PkScript))
			t.Logf("- 锁定脚本(hex): %x", out.PkScript)
		}

		// 11. 基本验证
		assert.Equal(t, common2.ReturnCode_SUCCESS, signedResp.Code, "返回码应该是成功")
		assert.NotEmpty(t, signedResp.SignedTxData, "已签名交易数据不应该为空")
		assert.NotEmpty(t, signedResp.Hash, "交易哈希不应该为空")
		assert.Equal(t, len(unsignedReq.Vin), len(signedTx.TxIn), "输入数量应该匹配")
		assert.Equal(t, len(unsignedReq.Vout), len(signedTx.TxOut), "输出数量应该匹配")

		// 12. 验证每个输入都有签名脚本
		for _, in := range signedTx.TxIn {
			assert.NotEmpty(t, in.SignatureScript, "每个输入都应该有签名脚本")
		}
	})

	// 可以添加更多测试用例
	t.Run("测试无效的签名", func(t *testing.T) {
		// ... 测试无效签名的情况
	})

	t.Run("测试签名数量不匹配", func(t *testing.T) {
		// ... 测试签名数量与输入不匹配的情况
	})
}

func TestSendSignedTransaction(t *testing.T) {
	// 1. 设置测试环境
	adaptor := setupChainAdaptor(t)

	// 2. 准备测试数据
	signedTxBase64 := "AQAAAAFEP+X98OG0svNckzVIk3vCAIuN28KJwtomAlLto59kGQAAAABrSDBFAiEA9VMLtJqtvJMxFEIAGbyvDBo14T8xTzxAT0lRWQQDx/gCIEqUVSfGvLItHFa3fZavgIoc2xKWab/HKz58FbDgoK0aASEDEDtz+OeJCuktBOImIHgfeTZVFVLkzg0OBhh2jAD4L8r/////AgBe0LIAAAAAFgAUpdPy3d+1gL+1ySO5e1oZYfOMHQTwbDV3AAAAABl2qRTZwBLk26kvV0EL8f9LxHRZ3qp024isAAAAAA=="

	t.Run("测试广播已签名交易", func(t *testing.T) {
		// 3. 解码Base64数据
		signedTxData, err := base64.StdEncoding.DecodeString(signedTxBase64)
		require.NoError(t, err, "解码Base64交易数据失败")

		// 4. 转换为hex字符串
		signedTxHex := hex.EncodeToString(signedTxData)

		// 5. 构建请求
		req := &utxo.SendTxRequest{
			ConsumerToken: "test_token",
			Chain:         ChainName,
			Network:       "simnet", // 根据您的需求选择网络：mainnet, testnet, simnet
			RawTx:         signedTxHex,
		}

		// 6. 发送交易
		resp, err := adaptor.SendTx(req)

		// 7. 打印详细信息用于调试
		t.Logf("Request: %+v", req)
		if err != nil {
			t.Logf("Error: %v", err)
			if resp != nil {
				t.Logf("Response: %+v", resp)
			}
		} else {
			t.Logf("Response: %+v", resp)
		}

		// 8. 验证结果
		require.NoError(t, err, "广播交易失败")
		require.NotNil(t, resp, "响应不能为空")
		assert.Equal(t, common2.ReturnCode_SUCCESS, resp.Code, "交易应该成功")
		assert.NotEmpty(t, resp.TxHash, "交易哈希不应为空")

		// 9. 可选：等待交易确认
		if err == nil {
			t.Logf("等待交易确认，交易哈希: %s", resp.TxHash)
			err = waitForConfirmation(adaptor, resp.TxHash, 1) // 等待1个确认
			require.NoError(t, err, "等待交易确认失败")
			t.Logf("交易已确认")
		}
	})
}

// 54029ce29e29bd396d031b61508412245d149694f3acb4c82239fe5b8faf8be9
// 辅助函数：等待交易确认
func waitForConfirmation(adaptor *ChainAdaptor, txHash string, confirmations int64) error {
	hash, err := chainhash.NewHashFromStr(txHash)
	if err != nil {
		return fmt.Errorf("invalid transaction hash: %v", err)
	}

	// 设置超时时间
	timeout := time.After(10 * time.Minute)
	tick := time.Tick(10 * time.Second)

	for {
		select {
		case <-timeout:
			return errors.New("confirmation timeout")
		case <-tick:
			// 使用 GetRawTransactionVerbose 替代 GetTransaction
			tx, err := adaptor.btcClient.GetRawTransactionVerbose(hash)
			if err != nil {
				// 如果是"transaction not found"错误，继续等待
				if strings.Contains(err.Error(), "Transaction not found") {
					continue
				}
				return err
			}

			if tx.Confirmations >= uint64(confirmations) {
				return nil
			}

			// 打印当前确认数
			log.Info("Waiting for confirmation",
				"txHash", txHash,
				"current_confirmations", tx.Confirmations,
				"target_confirmations", confirmations)
		}
	}
}

// 可选：打印交易详情的辅助函数
func printTransactionDetails(t *testing.T, txData []byte) {
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(txData)); err != nil {
		t.Logf("Failed to deserialize transaction: %v", err)
		return
	}

	t.Logf("\n=== 交易详情 ===")
	t.Logf("交易版本: %d", tx.Version)
	t.Logf("输入数量: %d", len(tx.TxIn))
	for i, in := range tx.TxIn {
		t.Logf("输入 #%d:", i)
		t.Logf("  前置交易: %s", in.PreviousOutPoint.Hash)
		t.Logf("  输出索引: %d", in.PreviousOutPoint.Index)
		t.Logf("  签名脚本长度: %d", len(in.SignatureScript))
		t.Logf("  序列号: %d", in.Sequence)
	}

	t.Logf("输出数量: %d", len(tx.TxOut))
	for i, out := range tx.TxOut {
		t.Logf("输出 #%d:", i)
		t.Logf("  金额: %d 聪 (%.8f BTC)", out.Value, float64(out.Value)/1e8)
		t.Logf("  锁定脚本长度: %d", len(out.PkScript))
	}
	t.Logf("锁定时间: %d", tx.LockTime)
}
