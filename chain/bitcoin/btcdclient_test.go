package bitcoin

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/assert"
)

const (
	baseURL     = "127.0.0.1:18556"
	rpcUser     = "jamie"
	rpcPassword = "123456"
)

func Test_Client_GetAddressUnspent(t *testing.T) {
	client, err := NewBtcdClient(baseURL, rpcUser, rpcPassword)
	assert.NoError(t, err, "BaseClient initialization failed")
	assert.NotNil(t, client, "BaseClient should not be nil")

	t.Run("GetAddressUnspent", func(t *testing.T) {
		// 使用测试地址（这是之前挖矿奖励的地址）
		const (
			// sb1q5hfl9hwlkkqtldwfywuhkksev8ecc8gy5w650w
			address = "SQW4z4BsNZKR42GP1752JqjEiG91PuFa3R"
		)

		unspents, err := client.GetAddressUnspent(address)
		assert.NoError(t, err, "failed to GetAddressUnspent")

		fmt.Printf("\n=== Address Unspent Information ===\n")
		fmt.Printf("Address: %s\n", address)
		fmt.Printf("Total UTXOs: %d\n", len(unspents))

		// 打印每个 UTXO 的详细信息
		for i, utxo := range unspents {
			fmt.Printf("\nUTXO #%d:\n", i+1)
			fmt.Printf("  TxID: %s\n", utxo.TxID)
			fmt.Printf("  Vout: %d\n", utxo.Vout)
			fmt.Printf("  Amount: %f BTC\n", utxo.Amount)
			fmt.Printf("  Confirmations: %d\n", utxo.Confirmations)
			fmt.Printf("  ScriptPubKey: %s\n", utxo.ScriptPubKey)

			// 验证 UTXO 字段
			assert.NotEmpty(t, utxo.TxID, "transaction ID should not be empty")
			assert.GreaterOrEqual(t, utxo.Amount, float64(0), "amount should be >= 0")
			assert.GreaterOrEqual(t, utxo.Confirmations, int64(0), "confirmations should be >= 0")
			assert.NotEmpty(t, utxo.ScriptPubKey, "scriptPubKey should not be empty")
		}
	})

	t.Run("GetAddressUnspent_InvalidAddress", func(t *testing.T) {
		// 测试无效地址
		invalidAddress := "invalid_address"

		unspents, err := client.GetAddressUnspent(invalidAddress)
		assert.Error(t, err, "should fail with invalid address")
		assert.Nil(t, unspents, "unspents should be nil for invalid address")

		fmt.Printf("\n=== Invalid Address Test ===\n")
		fmt.Printf("Address: %s\n", invalidAddress)
		fmt.Printf("Error: %v\n", err)
	})
}

func Test_Client_GetAddressBalance(t *testing.T) {
	client, err := NewBtcdClient(baseURL, rpcUser, rpcPassword)
	assert.NoError(t, err, "BaseClient initialization failed")
	assert.NotNil(t, client, "BaseClient should not be nil")

	t.Run("GetAddressBalance", func(t *testing.T) {
		// 使用测试地址
		const (
			// sb1q5hfl9hwlkkqtldwfywuhkksev8ecc8gy5w650w
			// SQW4z4BsNZKR42GP1752JqjEiG91PuFa3R
			address = "SQW4z4BsNZKR42GP1752JqjEiG91PuFa3R"
		)

		balance, err := client.GetAddressBalance(address)
		assert.NoError(t, err, "failed to GetAddressBalance")
		assert.NotEmpty(t, balance, "balance should not be empty")

		fmt.Printf("\n=== Address Balance Information ===\n")
		fmt.Printf("Address: %s\n", address)
		fmt.Printf("Balance: %s BTC\n", balance)

		// 验证余额格式和数值
		balanceFloat, err := strconv.ParseFloat(balance, 64)
		assert.NoError(t, err, "balance should be a valid number")
		assert.GreaterOrEqual(t, balanceFloat, float64(0), "balance should be >= 0")

		// 验证小数位数
		parts := strings.Split(balance, ".")
		if len(parts) > 1 {
			assert.LessOrEqual(t, len(parts[1]), 8, "balance should have at most 8 decimal places")
		}
	})

	t.Run("GetAddressBalance_InvalidAddress", func(t *testing.T) {
		// 测试无效地址
		invalidAddress := "invalid_address"

		balance, err := client.GetAddressBalance(invalidAddress)
		assert.Error(t, err, "should fail with invalid address")
		assert.Equal(t, "0", balance, "balance should be '0' for invalid address")

		fmt.Printf("\n=== Invalid Address Balance Test ===\n")
		fmt.Printf("Address: %s\n", invalidAddress)
		fmt.Printf("Balance: %s\n", balance)
		fmt.Printf("Error: %v\n", err)
	})

	t.Run("GetAddressBalance_EmptyAddress", func(t *testing.T) {
		// 测试空地址
		emptyAddress := ""

		balance, err := client.GetAddressBalance(emptyAddress)
		assert.Error(t, err, "should fail with empty address")
		assert.Equal(t, "0", balance, "balance should be '0' for empty address")

		fmt.Printf("\n=== Empty Address Balance Test ===\n")
		fmt.Printf("Address: %s\n", emptyAddress)
		fmt.Printf("Balance: %s\n", balance)
		fmt.Printf("Error: %v\n", err)
	})
}

func Test_Client_GetLatestBlockHash(t *testing.T) {
	client, err := NewBtcdClient(baseURL, rpcUser, rpcPassword)
	assert.NoError(t, err, "BaseClient initialization failed")
	assert.NotNil(t, client, "BaseClient should not be nil")

	// 5e8fde864104e5f5ca2511bcc6c8566074d141a8d17219b027877bae836c7519
	t.Run("GetLatestBlockHash", func(t *testing.T) {
		hash, err := client.GetLatestBlockHash()
		assert.NoError(t, err, "failed to GetLatestBlockHash")
		assert.NotNil(t, hash, "hash should not be nil")

		fmt.Printf("\n=== Latest Block Hash Information ===\n")
		fmt.Printf("Hash: %s\n", hash.String())
	})
}

func Test_Client_GetLatestBlock(t *testing.T) {
	client, err := NewBtcdClient(baseURL, rpcUser, rpcPassword)
	assert.NoError(t, err, "BaseClient initialization failed")
	assert.NotNil(t, client, "BaseClient should not be nil")

	t.Run("GetLatestBlock", func(t *testing.T) {
		// 5e8fde864104e5f5ca2511bcc6c8566074d141a8d17219b027877bae836c7519
		// 311
		hash, height, err := client.GetLatestBlock()
		assert.NoError(t, err, "failed to GetLatestBlock")
		assert.NotNil(t, hash, "hash should not be nil")

		fmt.Printf("\n=== Latest Block Information ===\n")
		fmt.Printf("Hash: %s\n", hash.String())
		fmt.Printf("Height: %d\n", height)

		assert.GreaterOrEqual(t, height, int32(0), "height should be greater than or equal to 0")
	})
}

func Test_Client_GetBlock(t *testing.T) {
	// Initialize BaseClient
	client, err := NewBtcdClient(baseURL, rpcUser, rpcPassword)
	assert.NoError(t, err, "BaseClient initialization failed")
	assert.NotNil(t, client, "BaseClient should not be nil")

	const (
		hash = "5e8fde864104e5f5ca2511bcc6c8566074d141a8d17219b027877bae836c7519"
	)

	t.Run("bitcoinclient GetBlock", func(t *testing.T) {
		blockHash, _ := chainhash.NewHashFromStr(hash)
		fmt.Printf("Testing block hash: %s\n", blockHash.String())

		resp, err := client.GetBlock(blockHash)
		respJson, _ := json.Marshal(resp)
		fmt.Println("bitcoinclient GetBlock resp", string(respJson))
		assert.NoError(t, err, "failed to GetBlock")
		assert.NotNil(t, resp, "response should not be nil")

		t.Run("Block Header Validation", func(t *testing.T) {
			fmt.Println("\n=== Block Header Information ===")
			fmt.Printf("Version: %d\n", resp.Header.Version)
			fmt.Printf("Previous Block: %s\n", resp.Header.PrevBlock.String())
			fmt.Printf("Merkle Root: %s\n", resp.Header.MerkleRoot.String())
			fmt.Printf("Timestamp: %v\n", resp.Header.Timestamp)
			fmt.Printf("Bits: %d\n", resp.Header.Bits)
			fmt.Printf("Nonce: %d\n", resp.Header.Nonce)

			assert.Greater(t, resp.Header.Version, int32(0), "block version should be greater than 0")
			assert.NotEmpty(t, resp.Header.PrevBlock, "previous block hash should not be empty")
			assert.NotEmpty(t, resp.Header.MerkleRoot, "merkle root should not be empty")
			assert.NotZero(t, resp.Header.Timestamp, "timestamp should not be zero")
			assert.Greater(t, resp.Header.Bits, uint32(0), "bits should be greater than 0")
			assert.NotZero(t, resp.Header.Nonce, "nonce should not be zero")
		})

		t.Run("Block Transactions Validation", func(t *testing.T) {
			fmt.Printf("\n=== Transaction Information ===\n")
			fmt.Printf("Total Transactions: %d\n", len(resp.Transactions))
			assert.GreaterOrEqual(t, len(resp.Transactions), 1, "should have at least one transaction")

			// 验证第一笔交易（coinbase 交易）
			if len(resp.Transactions) > 0 {
				tx := resp.Transactions[0]
				fmt.Println("\n--- Coinbase Transaction Details ---")
				fmt.Printf("Transaction Version: %d\n", tx.Version)
				fmt.Printf("Number of Inputs: %d\n", len(tx.TxIn))
				fmt.Printf("Number of Outputs: %d\n", len(tx.TxOut))
				fmt.Printf("Lock Time: %d\n", tx.LockTime)

				assert.Greater(t, tx.Version, int32(0), "transaction version should be greater than 0")
				assert.GreaterOrEqual(t, len(tx.TxIn), 1, "transaction should have at least one input")
				assert.GreaterOrEqual(t, len(tx.TxOut), 1, "transaction should have at least one output")

				fmt.Println("\nTransaction Inputs:")
				// 验证交易输入
				for index, txIn := range tx.TxIn {
					fmt.Printf("Input index #%d:\n", index)
					fmt.Printf("  Previous Outpoint Hash: %s\n", txIn.PreviousOutPoint.Hash.String())
					fmt.Printf("  Previous Outpoint Index: %d\n", txIn.PreviousOutPoint.Index)
					fmt.Printf("  Sequence: %d\n", txIn.Sequence)
					assert.NotNil(t, txIn, "transaction input should not be nil")
				}

				// 验证交易输出
				fmt.Println("\nTransaction Outputs:")
				for index, txOut := range tx.TxOut {
					fmt.Printf("Output #%d:\n", index)
					fmt.Printf("  Value: %d satoshis\n", txOut.Value)
					fmt.Printf("  Script Length: %d bytes\n", len(txOut.PkScript))
					assert.NotNil(t, txOut, "transaction output should not be nil")
				}
			}
		})
	})
}

func Test_Client_GetBlockVerbose(t *testing.T) {
	const (
		hash = "5e8fde864104e5f5ca2511bcc6c8566074d141a8d17219b027877bae836c7519"
	)
	// Initialize BaseClient
	client, err := NewBtcdClient(baseURL, rpcUser, rpcPassword)
	assert.NoError(t, err, "BaseClient initialization failed")
	assert.NotNil(t, client, "BaseClient should not be nil")

	t.Run("bitcoinclient GetBlock", func(t *testing.T) {
		blockHash, _ := chainhash.NewHashFromStr(hash)
		resp, err := client.GetBlockVerbose(blockHash)
		respJson, _ := json.Marshal(resp)
		fmt.Println("bitcoinclient GetBlockVerbose resp", string(respJson))
		assert.NoError(t, err, "failed to GetBlockVerbose")
		assert.NotNil(t, resp, "response should not be nil")

		t.Run("Node Info Validation", func(t *testing.T) {
			fmt.Println("\n=== Block Information ===")
			fmt.Printf("Block Hash: %s\n", resp.Hash)
			fmt.Printf("Confirmations: %d\n", resp.Confirmations)
			fmt.Printf("Stripped Size: %d\n", resp.StrippedSize)
			fmt.Printf("Size: %d\n", resp.Size)
			fmt.Printf("Weight: %d\n", resp.Weight)
			fmt.Printf("Height: %d\n", resp.Height)
			fmt.Printf("Version: %d (0x%s)\n", resp.Version, resp.VersionHex)
			fmt.Printf("Merkle Root: %s\n", resp.MerkleRoot)
			fmt.Printf("Time: %d\n", resp.Time)
			fmt.Printf("Nonce: %d\n", resp.Nonce)
			fmt.Printf("Bits: %s\n", resp.Bits)
			fmt.Printf("Difficulty: %f\n", resp.Difficulty)
			fmt.Printf("Previous Block Hash: %s\n", resp.PreviousHash)
			if resp.NextHash != "" {
				fmt.Printf("Next Block Hash: %s\n", resp.NextHash)
			}
			assert.NotEmpty(t, resp.Hash, "block hash should not be empty")
			assert.Greater(t, resp.Size, int32(0), "block size should be greater than 0")
			assert.Greater(t, resp.Weight, int32(0), "block weight should be greater than 0")
			assert.GreaterOrEqual(t, resp.Height, int64(0), "block height should be greater than or equal to 0")
			assert.Greater(t, resp.Version, int32(0), "version should be greater than 0")
			assert.NotEmpty(t, resp.VersionHex, "version hex should not be empty")
			assert.NotEmpty(t, resp.MerkleRoot, "merkle root should not be empty")
			assert.Greater(t, resp.Time, int64(0), "time should be greater than 0")
			assert.Greater(t, resp.Nonce, uint32(0), "nonce should be greater than 0")
			assert.NotEmpty(t, resp.Bits, "bits should not be empty")
			assert.Greater(t, resp.Difficulty, float64(0), "difficulty should be greater than 0")
			assert.NotEmpty(t, resp.PreviousHash, "previous hash should not be empty")
		})

		t.Run("Transaction List Validation", func(t *testing.T) {
			fmt.Printf("\n=== Transaction Information ===\n")
			fmt.Printf("Total Transactions: %d\n", len(resp.Tx))

			// 交易列表验证
			assert.GreaterOrEqual(t, len(resp.Tx), 1, "should have at least one transaction")

			fmt.Println("\nTransaction IDs:")
			for i, txid := range resp.Tx {
				if i < 5 { // 只打印前5个交易ID
					fmt.Printf("TX #%d: %s\n", i, txid)
				} else {
					fmt.Println("...")
					break
				}
			}

			// 验证第一个交易ID格式
			if len(resp.Tx) > 0 {
				assert.Regexp(t, "^[0-9a-f]{64}$", resp.Tx[0], "transaction ID should be a 64-character hex string")
			}
		})

		// 如果是详细模式2，验证原始交易信息
		if len(resp.RawTx) > 0 {
			t.Run("Raw Transaction Validation", func(t *testing.T) {
				fmt.Println("\n=== Raw Transaction Details ===")
				for i, rawTx := range resp.RawTx {
					if i >= 5 { // 只打印前5个交易的详细信息
						break
					}
					fmt.Printf("\nTransaction #%d:\n", i)
					fmt.Printf("TXID: %s\n", rawTx.Txid)
					fmt.Printf("Size: %d\n", rawTx.Size)
					fmt.Printf("Version: %d\n", rawTx.Version)
					fmt.Printf("Inputs: %d, Outputs: %d\n", len(rawTx.Vin), len(rawTx.Vout))
				}
			})
		}
	})
}

func Test_Client_GetBlockVerboseTx(t *testing.T) {
	const (
		hash = "5e8fde864104e5f5ca2511bcc6c8566074d141a8d17219b027877bae836c7519"
	)
	// Initialize BaseClient
	client, err := NewBtcdClient(baseURL, rpcUser, rpcPassword)
	assert.NoError(t, err, "BaseClient initialization failed")
	assert.NotNil(t, client, "BaseClient should not be nil")

	t.Run("bitcoinclient GetBlockVerboseTx", func(t *testing.T) {
		blockHash, _ := chainhash.NewHashFromStr(hash)
		resp, err := client.GetBlockVerboseTx(blockHash)
		respJson, _ := json.Marshal(resp)
		fmt.Println("bitcoinclient GetBlockVerboseTx resp", string(respJson))
		assert.NoError(t, err, "failed to GetBlockVerboseTx")
		assert.NotNil(t, resp, "response should not be nil")

		t.Run("Node Info Validation", func(t *testing.T) {
			fmt.Println("\n=== Block Information ===")
			fmt.Printf("Block Hash: %s\n", resp.Hash)
			fmt.Printf("Confirmations: %d\n", resp.Confirmations)
			fmt.Printf("Stripped Size: %d\n", resp.StrippedSize)
			fmt.Printf("Size: %d\n", resp.Size)
			fmt.Printf("Weight: %d\n", resp.Weight)
			fmt.Printf("Height: %d\n", resp.Height)
			fmt.Printf("Version: %d (0x%s)\n", resp.Version, resp.VersionHex)
			fmt.Printf("Merkle Root: %s\n", resp.MerkleRoot)
			fmt.Printf("Time: %d\n", resp.Time)
			fmt.Printf("Nonce: %d\n", resp.Nonce)
			fmt.Printf("Bits: %s\n", resp.Bits)
			fmt.Printf("Difficulty: %f\n", resp.Difficulty)
			fmt.Printf("Previous Block Hash: %s\n", resp.PreviousHash)
			if resp.NextHash != "" {
				fmt.Printf("Next Block Hash: %s\n", resp.NextHash)
			}

			// 基本信息验证
			assert.NotEmpty(t, resp.Hash, "block hash should not be empty")
			assert.Greater(t, resp.Size, int32(0), "block size should be greater than 0")
			assert.Greater(t, resp.Weight, int32(0), "block weight should be greater than 0")
			assert.GreaterOrEqual(t, resp.Height, int64(0), "block height should be greater than or equal to 0")
			assert.Greater(t, resp.Version, int32(0), "version should be greater than 0")
			assert.NotEmpty(t, resp.MerkleRoot, "merkle root should not be empty")
			assert.Greater(t, resp.Time, int64(0), "time should be greater than 0")
			assert.Greater(t, resp.Nonce, uint32(0), "nonce should be greater than 0")
			assert.NotEmpty(t, resp.Bits, "bits should not be empty")
			assert.Greater(t, resp.Difficulty, float64(0), "difficulty should be greater than 0")
		})

		t.Run("Detailed Transaction Validation", func(t *testing.T) {
			fmt.Printf("\n=== Transaction Details ===\n")
			fmt.Printf("Total Transactions: %d\n", len(GetBlockVerboseTx(resp)))
			assert.GreaterOrEqual(t, len(GetBlockVerboseTx(resp)), 1, "should have at least one transaction")

			// 验证前几个交易的详细信息
			for i, tx := range GetBlockVerboseTx(resp) {
				if i >= 5 { // 只打印前5个交易
					fmt.Println("...")
					break
				}
				fmt.Printf("\nTransaction #%d:\n", i)
				fmt.Printf("TXID: %s\n", tx.Txid)
				fmt.Printf("Size: %d bytes\n", tx.Size)
				fmt.Printf("Virtual Size: %d\n", tx.Vsize)
				fmt.Printf("Weight: %d\n", tx.Weight)
				fmt.Printf("Version: %d\n", tx.Version)
				fmt.Printf("Lock Time: %d\n", tx.LockTime)
				fmt.Printf("Input Count: %d\n", len(tx.Vin))
				fmt.Printf("Output Count: %d\n", len(tx.Vout))

				// 验证交易字段
				assert.NotEmpty(t, tx.Txid, "transaction ID should not be empty")
				assert.Greater(t, tx.Size, int32(0), "transaction size should be greater than 0")
				assert.Greater(t, tx.Version, uint32(0), "transaction version should be greater than 0")

				// 验证输入
				if len(tx.Vin) > 0 {
					fmt.Println("\nFirst Input Details:")
					fmt.Printf("  Txid: %s\n", tx.Vin[0].Txid)
					fmt.Printf("  Vout: %d\n", tx.Vin[0].Vout)
					if tx.Vin[0].ScriptSig != nil {
						fmt.Printf("  ScriptSig Asm: %s\n", tx.Vin[0].ScriptSig.Asm)
					}
				}

				// 验证输出
				if len(tx.Vout) > 0 {
					fmt.Println("\nFirst Output Details:")
					fmt.Printf("  Value: %f BTC\n", tx.Vout[0].Value)
					fmt.Printf("  Script Type: %s\n", tx.Vout[0].ScriptPubKey.Type)
					fmt.Printf("  Script Asm: %s\n", tx.Vout[0].ScriptPubKey.Asm)
				}
			}
		})
	})
}

func Test_Client_GetBlockHeader(t *testing.T) {
	const (
		hash = "5e8fde864104e5f5ca2511bcc6c8566074d141a8d17219b027877bae836c7519"
	)
	client, err := NewBtcdClient(baseURL, rpcUser, rpcPassword)
	assert.NoError(t, err, "BaseClient initialization failed")
	assert.NotNil(t, client, "BaseClient should not be nil")

	t.Run("GetBlockHeader", func(t *testing.T) {
		blockHash, _ := chainhash.NewHashFromStr(hash)
		header, err := client.GetBlockHeader(blockHash)
		assert.NoError(t, err, "failed to GetBlockHeader")
		assert.NotNil(t, header, "header should not be nil")

		fmt.Printf("\n=== Block Header Information ===\n")
		fmt.Printf("Version: %d\n", header.Version)
		fmt.Printf("Previous Block: %s\n", header.PrevBlock.String())
		fmt.Printf("Merkle Root: %s\n", header.MerkleRoot.String())
		fmt.Printf("Timestamp: %v\n", header.Timestamp)
		fmt.Printf("Bits: %d\n", header.Bits)
		fmt.Printf("Nonce: %d\n", header.Nonce)

		assert.Greater(t, header.Version, int32(0), "version should be greater than 0")
		assert.NotZero(t, header.Timestamp, "timestamp should not be zero")
	})
}

func Test_Client_GetBlockHeaderVerbose(t *testing.T) {
	const (
		hash = "5e8fde864104e5f5ca2511bcc6c8566074d141a8d17219b027877bae836c7519"
	)
	client, err := NewBtcdClient(baseURL, rpcUser, rpcPassword)
	assert.NoError(t, err, "BaseClient initialization failed")
	assert.NotNil(t, client, "BaseClient should not be nil")

	t.Run("GetBlockHeaderVerbose", func(t *testing.T) {
		blockHash, _ := chainhash.NewHashFromStr(hash)
		resp, err := client.GetBlockHeaderVerbose(blockHash)
		assert.NoError(t, err, "failed to GetBlockHeaderVerbose")
		assert.NotNil(t, resp, "response should not be nil")

		respJson, _ := json.Marshal(resp)
		fmt.Printf("\n=== Block Header Verbose Information ===\n")
		fmt.Printf("Response: %s\n", string(respJson))

		assert.NotEmpty(t, resp.Hash, "hash should not be empty")
		assert.GreaterOrEqual(t, resp.Height, int32(0), "height should be greater than or equal to 0")
	})
}

func Test_Client_GetBlockChainInfo(t *testing.T) {
	client, err := NewBtcdClient(baseURL, rpcUser, rpcPassword)
	assert.NoError(t, err, "BaseClient initialization failed")
	assert.NotNil(t, client, "BaseClient should not be nil")

	t.Run("GetBlockChainInfo", func(t *testing.T) {
		info, err := client.GetBlockChainInfo()
		assert.NoError(t, err, "failed to GetBlockChainInfo")
		assert.NotNil(t, info, "info should not be nil")

		respJson, _ := json.Marshal(info)
		fmt.Printf("\n=== Blockchain Information ===\n")
		fmt.Printf("Response: %s\n", string(respJson))

		fmt.Printf("\nDetailed Information:\n")
		fmt.Printf("Chain: %s\n", info.Chain)
		fmt.Printf("Blocks: %d\n", info.Blocks)
		fmt.Printf("Headers: %d\n", info.Headers)
		fmt.Printf("Best Block Hash: %s\n", info.BestBlockHash)
		fmt.Printf("Difficulty: %f\n", info.Difficulty)
		fmt.Printf("Verification Progress: %f\n", info.VerificationProgress)

		assert.NotEmpty(t, info.Chain, "chain should not be empty")
		assert.GreaterOrEqual(t, info.Blocks, int32(0), "blocks should be greater than or equal to 0")
	})
}

func Test_Client_GetBlockCount(t *testing.T) {
	client, err := NewBtcdClient(baseURL, rpcUser, rpcPassword)
	assert.NoError(t, err, "BaseClient initialization failed")
	assert.NotNil(t, client, "BaseClient should not be nil")

	t.Run("GetBlockCount", func(t *testing.T) {
		count, err := client.GetBlockCount()
		assert.NoError(t, err, "failed to GetBlockCount")

		fmt.Printf("\n=== Block Count Information ===\n")
		fmt.Printf("Total Blocks: %d\n", count)

		assert.GreaterOrEqual(t, count, int64(0), "block count should be greater than or equal to 0")
	})
}

func Test_Client_GetBlockHashByHeight(t *testing.T) {
	client, err := NewBtcdClient(baseURL, rpcUser, rpcPassword)
	assert.NoError(t, err, "BaseClient initialization failed")
	assert.NotNil(t, client, "BaseClient should not be nil")

	t.Run("GetBlockHashByHeight", func(t *testing.T) {
		// 测试创世区块（高度为0）
		height := int64(0)
		hash, err := client.GetBlockHashByHeight(height)
		assert.NoError(t, err, "failed to GetBlockHashByHeight")
		assert.NotEmpty(t, hash, "hash should not be empty")

		fmt.Printf("\n=== Block Hash by Height Information ===\n")
		fmt.Printf("Height: %d\n", height)
		fmt.Printf("Hash: %s\n", hash)

		// 验证哈希格式
		assert.Regexp(t, "^[0-9a-f]{64}$", hash, "hash should be a 64-character hex string")
	})

	t.Run("GetBlockHashByHeight v2", func(t *testing.T) {
		// 测试创世区块（高度为0）
		height := int64(311)
		hash, err := client.GetBlockHashByHeight(height)
		assert.NoError(t, err, "failed to GetBlockHashByHeight")
		assert.NotEmpty(t, hash, "hash should not be empty")

		fmt.Printf("\n=== Block Hash by Height Information ===\n")
		fmt.Printf("Height: %d\n", height)
		fmt.Printf("Hash: %s\n", hash)

		// 验证哈希格式
		assert.Regexp(t, "^[0-9a-f]{64}$", hash, "hash should be a 64-character hex string")
	})
}
