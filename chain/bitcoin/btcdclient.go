package bitcoin

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/ethereum/go-ethereum/log"
	"strconv"
)

type BtcdClient interface {
	GetAddressUnspent(address string) ([]btcjson.ListUnspentResult, error)
	GetAddressBalance(address string) (string, error)

	GetLatestBlockHash() (*chainhash.Hash, error)
	GetLatestBlock() (*chainhash.Hash, int32, error)
	GetBlock(blockHash *chainhash.Hash) (*wire.MsgBlock, error)
	GetBlockVerbose(blockHash *chainhash.Hash) (*btcjson.GetBlockVerboseResult, error)
	GetBlockVerboseTx(blockHash *chainhash.Hash) (*btcjson.GetBlockVerboseTxResult, error)
	GetBlockHeader(blockHash *chainhash.Hash) (*wire.BlockHeader, error)
	GetBlockHeaderVerbose(blockHash *chainhash.Hash) (*btcjson.GetBlockHeaderVerboseResult, error)
	GetBlockChainInfo() (*btcjson.GetBlockChainInfoResult, error)
	GetBlockCount() (int64, error)
	GetBlockHashByHeight(blockHeight int64) (string, error)
}

func NewBtcdClient(RpcUrl, RpcUser, RpcPass string) (BtcdClient, error) {
	if RpcUrl == "" || RpcUser == "" || RpcPass == "" {
		return nil, fmt.Errorf("RPC参数不能为空")
	}

	client, err := rpcclient.New(&rpcclient.ConnConfig{
		Host:         RpcUrl,
		User:         RpcUser,
		Pass:         RpcPass,
		HTTPPostMode: true,
		DisableTLS:   true,
	}, nil)
	if err != nil {
		log.Error("创建比特币RPC客户端失败", "err", err)
		return nil, fmt.Errorf("创建RPC客户端失败: %v", err)
	}

	// 验证连接
	_, err = client.GetBlockCount()
	if err != nil {
		log.Error("验证RPC连接失败", "err", err)
		return nil, fmt.Errorf("RPC连接验证失败: %v", err)
	}

	return &baseclient{
		rpcClient:  client,
		compressed: true,
	}, nil
}

type baseclient struct {
	rpcClient  *rpcclient.Client
	compressed bool
}

func (base *baseclient) GetAddressUnspent(address string) ([]btcjson.ListUnspentResult, error) {
	// 创建地址对象
	addr, err := btcutil.DecodeAddress(address, &chaincfg.SimNetParams)
	if err != nil {
		return nil, fmt.Errorf("解析地址失败: %v", err)
	}

	// 存储所有交易
	var allTransactions []*wire.MsgTx
	skip := 0
	const batchSize = 100

	// 循环获取所有交易
	for {
		transactions, err := base.rpcClient.SearchRawTransactions(addr, skip, batchSize, false, nil)
		if err != nil {
			// 如果是因为没有更多交易导致的错误，则退出循环
			if skip > 0 {
				break
			}
			return nil, fmt.Errorf("搜索交易失败: %v", err)
		}

		// 如果没有获取到新交易，退出循环
		if len(transactions) == 0 {
			break
		}

		allTransactions = append(allTransactions, transactions...)

		// 如果获取的交易数小于批次大小，说明已经没有更多交易
		if len(transactions) < batchSize {
			break
		}

		skip += batchSize
	}

	// 解析交易找出未花费输出
	unspents := make([]btcjson.ListUnspentResult, 0)
	spentOutputs := make(map[string]bool)

	// 首先记录所有已花费的输出
	for _, tx := range allTransactions {
		for _, input := range tx.TxIn {
			key := fmt.Sprintf("%v:%v", input.PreviousOutPoint.Hash, input.PreviousOutPoint.Index)
			spentOutputs[key] = true
		}
	}

	// 然后找出未花费的输出
	for _, tx := range allTransactions {
		txHash := tx.TxHash()
		for i, output := range tx.TxOut {
			// 检查输出是否属于目标地址
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.PkScript, &chaincfg.SimNetParams)
			if err != nil {
				continue
			}

			for _, a := range addrs {
				if a.String() == address {
					key := fmt.Sprintf("%v:%v", txHash, i)
					if !spentOutputs[key] {
						// 获取交易确认数
						confirmations := uint64(0)
						txDetails, err := base.rpcClient.GetRawTransactionVerbose(&txHash)
						if err == nil {
							confirmations = txDetails.Confirmations
						}

						unspent := btcjson.ListUnspentResult{
							TxID:          txHash.String(),
							Vout:          uint32(i),
							Address:       address,
							Amount:        btcutil.Amount(output.Value).ToBTC(),
							Confirmations: int64(confirmations),
							ScriptPubKey:  hex.EncodeToString(output.PkScript),
						}
						unspents = append(unspents, unspent)
					}
				}
			}
		}
	}

	return unspents, nil
}

func (base *baseclient) GetAddressBalance(address string) (string, error) {
	// 获取地址的所有UTXO
	unspents, err := base.GetAddressUnspent(address)
	if err != nil {
		return "0", err
	}

	// 计算总余额
	var totalAmount float64
	for _, utxo := range unspents {
		totalAmount += utxo.Amount
	}

	// 转换为字符串，保留8位小数
	balance := strconv.FormatFloat(totalAmount, 'f', 8, 64)
	return balance, nil
}

// GetLatestBlockHash 获取最新区块的哈希值
func (base *baseclient) GetLatestBlockHash() (*chainhash.Hash, error) {
	if base.rpcClient == nil {
		return nil, fmt.Errorf("RPC客户端未初始化")
	}

	hash, err := base.rpcClient.GetBestBlockHash()
	if err != nil {
		log.Error("获取最新区块哈希失败", "err", err)
		return nil, fmt.Errorf("获取最新区块哈希失败: %v", err)
	}

	log.Debug("获取最新区块哈希成功", "hash", hash.String())
	return hash, nil
}

// GetLatestBlock 获取最新区块的哈希值和高度
func (base *baseclient) GetLatestBlock() (*chainhash.Hash, int32, error) {
	if base.rpcClient == nil {
		return nil, 0, fmt.Errorf("RPC客户端未初始化")
	}

	hash, height, err := base.rpcClient.GetBestBlock()
	if err != nil {
		log.Error("获取最新区块信息失败", "err", err)
		return nil, 0, fmt.Errorf("获取最新区块信息失败: %v", err)
	}

	log.Debug("获取最新区块信息成功", "hash", hash.String(), "height", height)
	return hash, height, nil
}

// GetBlock 获取指定哈希值的区块详细信息
func (base *baseclient) GetBlock(blockHash *chainhash.Hash) (*wire.MsgBlock, error) {
	if base.rpcClient == nil {
		return nil, fmt.Errorf("RPC客户端未初始化")
	}
	if blockHash == nil {
		return nil, fmt.Errorf("区块哈希参数不能为空")
	}

	block, err := base.rpcClient.GetBlock(blockHash)
	if err != nil {
		log.Error("获取区块信息失败", "hash", blockHash.String(), "err", err)
		return nil, fmt.Errorf("获取区块信息失败: %v", err)
	}

	log.Debug("获取区块信息成功", "hash", blockHash.String())
	return block, nil
}

// GetBlockVerbose 获取区块的详细信息（不包含交易详情）
func (base *baseclient) GetBlockVerbose(blockHash *chainhash.Hash) (*btcjson.GetBlockVerboseResult, error) {
	if base.rpcClient == nil {
		return nil, fmt.Errorf("RPC客户端未初始化")
	}
	if blockHash == nil {
		return nil, fmt.Errorf("区块哈希参数不能为空")
	}

	block, err := base.rpcClient.GetBlockVerbose(blockHash)
	if err != nil {
		log.Error("获取区块详细信息失败", "hash", blockHash.String(), "err", err)
		return nil, fmt.Errorf("获取区块详细信息失败: %v", err)
	}

	log.Debug("获取区块详细信息成功", "hash", blockHash.String())
	return block, nil
}

// GetBlockHeader 获取区块头信息
func (base *baseclient) GetBlockHeader(blockHash *chainhash.Hash) (*wire.BlockHeader, error) {
	if base.rpcClient == nil {
		return nil, fmt.Errorf("RPC客户端未初始化")
	}
	if blockHash == nil {
		return nil, fmt.Errorf("区块哈希参数不能为空")
	}

	header, err := base.rpcClient.GetBlockHeader(blockHash)
	if err != nil {
		log.Error("获取区块头信息失败", "hash", blockHash.String(), "err", err)
		return nil, fmt.Errorf("获取区块头信息失败: %v", err)
	}

	log.Debug("获取区块头信息成功", "hash", blockHash.String())
	return header, nil
}

// GetBlockHeaderVerbose 获取区块头的详细信息
func (base *baseclient) GetBlockHeaderVerbose(blockHash *chainhash.Hash) (*btcjson.GetBlockHeaderVerboseResult, error) {
	if base.rpcClient == nil {
		return nil, fmt.Errorf("RPC客户端未初始化")
	}
	if blockHash == nil {
		return nil, fmt.Errorf("区块哈希参数不能为空")
	}

	header, err := base.rpcClient.GetBlockHeaderVerbose(blockHash)
	if err != nil {
		log.Error("获取区块头详细信息失败", "hash", blockHash.String(), "err", err)
		return nil, fmt.Errorf("获取区块头详细信息失败: %v", err)
	}

	log.Debug("获取区块头详细信息成功", "hash", blockHash.String())
	return header, nil
}

// GetBlockVerboseTx 获取区块的详细信息（包含交易详情）
func (base *baseclient) GetBlockVerboseTx(blockHash *chainhash.Hash) (*btcjson.GetBlockVerboseTxResult, error) {
	if base.rpcClient == nil {
		return nil, fmt.Errorf("RPC客户端未初始化")
	}
	if blockHash == nil {
		return nil, fmt.Errorf("区块哈希参数不能为空")
	}

	block, err := base.rpcClient.GetBlockVerboseTx(blockHash)
	if err != nil {
		log.Error("获取区块详细信息(含交易)失败", "hash", blockHash.String(), "err", err)
		return nil, fmt.Errorf("获取区块详细信息(含交易)失败: %v", err)
	}

	log.Debug("获取区块详细信息(含交易)成功", "hash", blockHash.String())
	return block, nil
}

func GetBlockVerboseTx(req *btcjson.GetBlockVerboseTxResult) []btcjson.TxRawResult {
	if len(req.Tx) > 0 {
		return req.Tx
	}
	return req.RawTx
}

// GetBlockChainInfo 获取区块链信息
func (base *baseclient) GetBlockChainInfo() (*btcjson.GetBlockChainInfoResult, error) {
	if base.rpcClient == nil {
		return nil, fmt.Errorf("RPC客户端未初始化")
	}

	info, err := base.rpcClient.GetBlockChainInfo()
	if err != nil {
		log.Error("获取区块链信息失败", "err", err)
		return nil, fmt.Errorf("获取区块链信息失败: %v", err)
	}

	log.Debug("获取区块链信息成功")
	return info, nil
}

// GetBlockCount 获取区块总数
func (base *baseclient) GetBlockCount() (int64, error) {
	if base.rpcClient == nil {
		return 0, fmt.Errorf("RPC客户端未初始化")
	}

	count, err := base.rpcClient.GetBlockCount()
	if err != nil {
		log.Error("获取区块总数失败", "err", err)
		return 0, fmt.Errorf("获取区块总数失败: %v", err)
	}

	log.Debug("获取区块总数成功", "count", count)
	return count, nil
}

// GetBlockHashByHeight 根据区块高度获取区块哈希
func (base *baseclient) GetBlockHashByHeight(blockHeight int64) (string, error) {
	if base.rpcClient == nil {
		return "", fmt.Errorf("RPC客户端未初始化")
	}
	if blockHeight < 0 {
		return "", fmt.Errorf("区块高度不能为负数")
	}

	hash, err := base.rpcClient.GetBlockHash(blockHeight)
	if err != nil {
		log.Error("获取区块哈希失败", "height", blockHeight, "err", err)
		return "", fmt.Errorf("获取区块哈希失败(高度:%d): %v", blockHeight, err)
	}

	log.Debug("获取区块哈希成功", "height", blockHeight, "hash", hash.String())
	return hash.String(), nil
}
