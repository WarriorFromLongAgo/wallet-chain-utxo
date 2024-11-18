package bitcoin

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/dapplink-labs/wallet-chain-utxo/chain/bitcoin/types"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/log"
	"github.com/pkg/errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/dapplink-labs/wallet-chain-utxo/chain"
	"github.com/dapplink-labs/wallet-chain-utxo/chain/base"
	"github.com/dapplink-labs/wallet-chain-utxo/config"
	common2 "github.com/dapplink-labs/wallet-chain-utxo/rpc/common"
	"github.com/dapplink-labs/wallet-chain-utxo/rpc/utxo"
)

const ChainName = "Bitcoin"

const (
	AddressFormatP2PKH  = "p2pkh"
	AddressFormatP2WPKH = "p2wpkh"
	AddressFormatP2SH   = "p2sh"
	AddressFormatP2TR   = "p2tr"
)

type ChainAdaptor struct {
	btcClient       base.BaseClient
	btcdClient      BtcdClient
	btcDataClient   *base.BaseDataClient
	thirdPartClient *BcClient
}

func NewChainAdaptor(conf *config.Config) (chain.IChainAdaptor, error) {
	baseClient, err := base.NewBaseClient(conf.WalletNode.Btc.RpcUrl, conf.WalletNode.Btc.RpcUser, conf.WalletNode.Btc.RpcPass)
	if err != nil {
		log.Error("new bitcoin rpc client fail", "err", err)
		return nil, err
	}
	baseDataClient, err := base.NewBaseDataClient(conf.WalletNode.Btc.DataApiUrl, conf.WalletNode.Btc.DataApiKey, "BTC", "Bitcoin")
	if err != nil {
		log.Error("new bitcoin data client fail", "err", err)
		return nil, err
	}
	bcClient, err := NewBlockChainClient(conf.WalletNode.Btc.TpApiUrl)
	if err != nil {
		log.Error("new blockchain client fail", "err", err)
		return nil, err
	}
	bccdClient, err := NewBtcdClient(conf.WalletNode.Btc.RpcUrl, conf.WalletNode.Btc.RpcUser, conf.WalletNode.Btc.RpcPass)
	if err != nil {
		log.Error("new blockchain client fail", "err", err)
		return nil, err
	}
	return &ChainAdaptor{
		btcClient:       *baseClient,
		btcdClient:      bccdClient,
		btcDataClient:   baseDataClient,
		thirdPartClient: bcClient,
	}, nil
}

func (c *ChainAdaptor) GetSupportChains(req *utxo.SupportChainsRequest) (*utxo.SupportChainsResponse, error) {
	response := &utxo.SupportChainsResponse{
		Code:    common2.ReturnCode_ERROR,
		Msg:     "",
		Support: false,
	}

	if ok, msg := validateChainAndNetwork(req.Chain, req.Network); !ok {
		err := fmt.Errorf("GetSupportChains validateChainAndNetwork fail, err msg = %s", msg)
		log.Error("err", err)
		response.Msg = err.Error()
		return response, err
	}

	response.Msg = "Support this chain"
	response.Code = common2.ReturnCode_SUCCESS
	response.Support = true
	return response, nil
}

func (c *ChainAdaptor) ConvertAddress(req *utxo.ConvertAddressRequest) (*utxo.ConvertAddressResponse, error) {
	response := &utxo.ConvertAddressResponse{
		Code:    common2.ReturnCode_ERROR,
		Msg:     "",
		Address: "",
	}

	if ok, msg := validateChainAndNetwork(req.Chain, req.Network); !ok {
		err := fmt.Errorf("ConvertAddress validateChainAndNetwork fail, err msg = %s", msg)
		log.Error("err", err)
		response.Msg = err.Error()
		return response, err
	}

	var address string
	compressedPubKeyBytes, _ := hex.DecodeString(req.PublicKey)
	pubKeyHash := btcutil.Hash160(compressedPubKeyBytes)

	switch req.Format {
	case AddressFormatP2PKH:
		p2pkhAddr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
		if err != nil {
			log.Error("create p2pkh address fail", "err", err)
			return nil, err
		}
		address = p2pkhAddr.EncodeAddress()
		break
	case AddressFormatP2WPKH:
		witnessAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
		if err != nil {
			log.Error("create p2wpkh fail", "err", err)
		}
		address = witnessAddr.EncodeAddress()
		break
	case AddressFormatP2SH:
		witnessAddr, _ := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
		script, err := txscript.PayToAddrScript(witnessAddr)
		if err != nil {
			log.Error("create p2sh address script fail", "err", err)
			return nil, err
		}
		p2shAddr, err := btcutil.NewAddressScriptHash(script, &chaincfg.MainNetParams)
		if err != nil {
			log.Error("create p2sh address fail", "err", err)
			return nil, err
		}
		address = p2shAddr.EncodeAddress()
		break
	case AddressFormatP2TR:
		pubKey, err := btcec.ParsePubKey(compressedPubKeyBytes)
		if err != nil {
			log.Error("parse public key fail", "err", err)
			return nil, err
		}
		taprootPubKey := schnorr.SerializePubKey(pubKey)
		taprootAddr, err := btcutil.NewAddressTaproot(taprootPubKey, &chaincfg.MainNetParams)
		if err != nil {
			log.Error("create taproot address fail", "err", err)
			return nil, err
		}
		address = taprootAddr.EncodeAddress()
	default:
		return nil, errors.New("Do not support address type")
	}

	response.Code = common2.ReturnCode_SUCCESS
	response.Msg = "convert address success"
	response.Address = address
	return response, nil
}

func (c *ChainAdaptor) ValidAddress(req *utxo.ValidAddressRequest) (*utxo.ValidAddressResponse, error) {
	response := &utxo.ValidAddressResponse{
		Code:  common2.ReturnCode_ERROR,
		Msg:   "",
		Valid: false,
	}
	if ok, msg := validateChainAndNetwork(req.Chain, req.Network); !ok {
		err := fmt.Errorf("ValidAddress validateChainAndNetwork fail, err msg = %s", msg)
		log.Error("err", err)
		response.Msg = err.Error()
		return response, err
	}
	address, err := btcutil.DecodeAddress(req.Address, &chaincfg.MainNetParams)
	if err != nil {
		err := fmt.Errorf("ValidAddress DecodeAddress failed: %w", err)
		log.Error("err", err)
		response.Msg = err.Error()
		return nil, err
	}
	// is MainNet flag
	if !address.IsForNet(&chaincfg.MainNetParams) {
		err := fmt.Errorf("ValidAddress IsForNet failed: %w", err)
		log.Error("err", err)
		response.Msg = err.Error()
		return nil, err
	}
	response.Valid = true
	response.Code = common2.ReturnCode_SUCCESS
	response.Msg = "ValidAddress success"
	return response, nil
}

func (c *ChainAdaptor) GetFee(req *utxo.FeeRequest) (*utxo.FeeResponse, error) {
	gasFeeResp, err := c.btcDataClient.GetFee()
	if err != nil {
		return &utxo.FeeResponse{
			Code: common2.ReturnCode_ERROR,
			Msg:  err.Error(),
		}, err
	}
	return &utxo.FeeResponse{
		Code:       common2.ReturnCode_SUCCESS,
		Msg:        "get fee success",
		BestFee:    gasFeeResp.BestTransactionFee,
		BestFeeSat: gasFeeResp.BestTransactionFeeSat,
		SlowFee:    gasFeeResp.SlowGasPrice,
		NormalFee:  gasFeeResp.StandardGasPrice,
		FastFee:    gasFeeResp.RapidGasPrice,
	}, nil
}

func (c *ChainAdaptor) GetAccount(req *utxo.AccountRequest) (*utxo.AccountResponse, error) {
	if req == nil || req.Address == "" {
		return &utxo.AccountResponse{
			Code:    common2.ReturnCode_ERROR,
			Msg:     "invalid parameters",
			Balance: "0",
		}, fmt.Errorf("invalid parameters")
	}

	balance, err := c.thirdPartClient.GetAccountBalance(req.Address)
	if err != nil {
		return &utxo.AccountResponse{
			Code:    common2.ReturnCode_ERROR,
			Msg:     "get btc balance fail",
			Balance: "0",
		}, err
	}

	return &utxo.AccountResponse{
		Code:    common2.ReturnCode_SUCCESS,
		Msg:     "get btc balance success",
		Balance: balance,
	}, nil
}

func (c *ChainAdaptor) GetUnspentOutputs(req *utxo.UnspentOutputsRequest) (*utxo.UnspentOutputsResponse, error) {
	utxoList, err := c.thirdPartClient.GetAccountUtxo(req.Address)
	if err != nil {
		return &utxo.UnspentOutputsResponse{
			Code:           common2.ReturnCode_ERROR,
			Msg:            err.Error(),
			UnspentOutputs: nil,
		}, err
	}
	var unspentOutputList []*utxo.UnspentOutput
	for _, value := range utxoList {
		unspentOutput := &utxo.UnspentOutput{
			TxHashBigEndian: value.TxHashBigEndian,
			TxId:            value.TxHash,
			TxOutputN:       value.TxOutputN,
			Script:          value.Script,
			UnspentAmount:   strconv.FormatUint(value.Value, 10),
			Index:           value.TxIndex,
		}
		unspentOutputList = append(unspentOutputList, unspentOutput)
	}
	return &utxo.UnspentOutputsResponse{
		Code:           common2.ReturnCode_SUCCESS,
		Msg:            "get unspent outputs success",
		UnspentOutputs: unspentOutputList,
	}, nil
}

func (c *ChainAdaptor) GetBlockByNumber(req *utxo.BlockNumberRequest) (*utxo.BlockResponse, error) {
	blockHash, err := c.btcClient.GetBlockHash(req.Height)
	if err != nil {
		log.Error("get block hash by number fail", "err", err)
		return &utxo.BlockResponse{
			Code: common2.ReturnCode_ERROR,
			Msg:  "get block hash fail",
		}, err
	}
	var params []json.RawMessage
	numBlocksJSON, _ := json.Marshal(blockHash)
	params = []json.RawMessage{numBlocksJSON}
	block, _ := c.btcClient.Client.RawRequest("getblock", params)
	var resultBlock types.BlockData
	err = json.Unmarshal(block, &resultBlock)
	if err != nil {
		log.Error("Unmarshal json fail", "err", err)
	}
	var txList []*utxo.TransactionList
	for _, txid := range resultBlock.Tx {
		txIdJson, _ := json.Marshal(txid)
		boolJSON, _ := json.Marshal(true)
		dataJSON := []json.RawMessage{txIdJson, boolJSON}
		tx, err := c.btcClient.Client.RawRequest("getrawtransaction", dataJSON)
		if err != nil {
			fmt.Println("get raw transaction fail", "err", err)
		}
		var rawTx types.RawTransactionData
		err = json.Unmarshal(tx, &rawTx)
		if err != nil {
			log.Error("json unmarshal fail", "err", err)
			return nil, err
		}
		var vinList []*utxo.Vin
		for _, vin := range rawTx.Vin {
			vinItem := &utxo.Vin{
				Hash:    vin.TxId,
				Index:   uint32(vin.Vout),
				Amount:  10,
				Address: vin.ScriptSig.Asm,
			}
			vinList = append(vinList, vinItem)
		}
		var voutList []*utxo.Vout
		for _, vout := range rawTx.Vout {
			voutItem := &utxo.Vout{
				Address: vout.ScriptPubKey.Address,
				Amount:  int64(vout.Value),
			}
			voutList = append(voutList, voutItem)
		}
		txItem := &utxo.TransactionList{
			Hash: rawTx.Hash,
			Vin:  vinList,
			Vout: voutList,
		}
		txList = append(txList, txItem)
	}
	return &utxo.BlockResponse{
		Code:   common2.ReturnCode_SUCCESS,
		Msg:    "get block by number succcess",
		Height: uint64(req.Height),
		//Hash:   blockHash.String(),
		//TxList: txList,
	}, nil
}

func (c *ChainAdaptor) GetBlockByHash(req *utxo.BlockHashRequest) (*utxo.BlockResponse, error) {
	var params []json.RawMessage
	numBlocksJSON, _ := json.Marshal(req.Hash)
	params = []json.RawMessage{numBlocksJSON}
	block, _ := c.btcClient.Client.RawRequest("getblock", params)
	var resultBlock types.BlockData
	err := json.Unmarshal(block, &resultBlock)
	if err != nil {
		log.Error("Unmarshal json fail", "err", err)
	}
	var txList []*utxo.TransactionList
	for _, txid := range resultBlock.Tx {
		txIdJson, _ := json.Marshal(txid)
		boolJSON, _ := json.Marshal(true)
		dataJSON := []json.RawMessage{txIdJson, boolJSON}
		tx, err := c.btcClient.Client.RawRequest("getrawtransaction", dataJSON)
		if err != nil {
			fmt.Println("get raw transaction fail", "err", err)
		}
		var rawTx types.RawTransactionData
		err = json.Unmarshal(tx, &rawTx)
		if err != nil {
			log.Error("json unmarshal fail", "err", err)
			return nil, err
		}
		var vinList []*utxo.Vin
		for _, vin := range rawTx.Vin {
			vinItem := &utxo.Vin{
				Hash:    vin.TxId,
				Index:   uint32(vin.Vout),
				Amount:  10,
				Address: vin.ScriptSig.Asm,
			}
			vinList = append(vinList, vinItem)
		}
		var voutList []*utxo.Vout
		for _, vout := range rawTx.Vout {
			voutItem := &utxo.Vout{
				Address: vout.ScriptPubKey.Address,
				Amount:  int64(vout.Value),
			}
			voutList = append(voutList, voutItem)
		}
		txItem := &utxo.TransactionList{
			Hash: rawTx.Hash,
			Vin:  vinList,
			Vout: voutList,
		}
		txList = append(txList, txItem)
	}
	return &utxo.BlockResponse{
		Code:   common2.ReturnCode_SUCCESS,
		Msg:    "get block by number succcess",
		Height: resultBlock.Height,
		Hash:   req.Hash,
		TxList: txList,
	}, nil
}

func (c *ChainAdaptor) GetBlockHeaderByHash(req *utxo.BlockHeaderHashRequest) (*utxo.BlockHeaderResponse, error) {
	hash, err := chainhash.NewHashFromStr(req.Hash)
	if err != nil {
		log.Error("format string to hash fail", "err", err)
	}
	blockHeader, err := c.btcClient.Client.GetBlockHeader(hash)
	if err != nil {
		return &utxo.BlockHeaderResponse{
			Code: common2.ReturnCode_ERROR,
			Msg:  "get block header fail",
		}, err
	}
	return &utxo.BlockHeaderResponse{
		Code:       common2.ReturnCode_SUCCESS,
		Msg:        "get block header success",
		ParentHash: blockHeader.PrevBlock.String(),
		Number:     string(blockHeader.Version),
		BlockHash:  req.Hash,
		MerkleRoot: blockHeader.MerkleRoot.String(),
	}, nil
}

func (c *ChainAdaptor) GetBlockHeaderByNumber(req *utxo.BlockHeaderNumberRequest) (*utxo.BlockHeaderResponse, error) {
	blockNumber := req.Height
	if req.Height == 0 {
		latestBlock, err := c.btcClient.Client.GetBlockCount()
		if err != nil {
			return &utxo.BlockHeaderResponse{
				Code: common2.ReturnCode_ERROR,
				Msg:  "get latest block fail",
			}, err
		}
		blockNumber = latestBlock
	}
	blockHash, err := c.btcClient.Client.GetBlockHash(blockNumber)
	if err != nil {
		log.Error("get block hash by number fail", "err", err)
		return &utxo.BlockHeaderResponse{
			Code: common2.ReturnCode_ERROR,
			Msg:  "get block hash fail",
		}, err
	}
	blockHeader, err := c.btcClient.Client.GetBlockHeader(blockHash)
	if err != nil {
		return &utxo.BlockHeaderResponse{
			Code: common2.ReturnCode_ERROR,
			Msg:  "get block header fail",
		}, err
	}
	return &utxo.BlockHeaderResponse{
		Code:       common2.ReturnCode_SUCCESS,
		Msg:        "get block header success",
		ParentHash: blockHeader.PrevBlock.String(),
		Number:     strconv.FormatInt(blockNumber, 10),
		BlockHash:  blockHash.String(),
		MerkleRoot: blockHeader.MerkleRoot.String(),
	}, nil
}

func (c *ChainAdaptor) SendTx(req *utxo.SendTxRequest) (*utxo.SendTxResponse, error) {
	if req == nil || len(req.RawTx) == 0 {
		return &utxo.SendTxResponse{
			Code: common2.ReturnCode_ERROR,
			Msg:  "invalid request parameters",
		}, errors.New("invalid request parameters")
	}
	if ok, msg := validateChainAndNetwork(req.Chain, req.Network); !ok {
		return &utxo.SendTxResponse{
			Code: common2.ReturnCode_ERROR,
			Msg:  msg,
		}, errors.New(msg)
	}
	rawTxBytes, err := hex.DecodeString(req.RawTx)
	if err != nil {
		return &utxo.SendTxResponse{
			Code: common2.ReturnCode_ERROR,
			Msg:  "invalid raw transaction hex: " + err.Error(),
		}, err
	}

	var msgTx wire.MsgTx
	if err := msgTx.Deserialize(bytes.NewReader(rawTxBytes)); err != nil {
		return &utxo.SendTxResponse{
			Code: common2.ReturnCode_ERROR,
			Msg:  "failed to deserialize transaction: " + err.Error(),
		}, err
	}

	txHash, err := c.btcClient.SendRawTransaction(&msgTx, true)
	if err != nil {
		return &utxo.SendTxResponse{
			Code: common2.ReturnCode_ERROR,
			Msg:  err.Error(),
		}, err
	}
	// 6. 验证交易哈希
	localHash := msgTx.TxHash()
	if localHash.String() != txHash.String() {
		log.Error("transaction hash mismatch",
			"local_hash", localHash.String(),
			"network_hash", txHash.String(),
			"raw_tx", req.RawTx)
		// 注意：这里可以选择是否要返回错误，因为哈希不匹配可能表示潜在问题
	}
	return &utxo.SendTxResponse{
		Code:   common2.ReturnCode_SUCCESS,
		Msg:    "send tx success",
		TxHash: txHash.String(),
	}, nil
}

func (c *ChainAdaptor) GetTxByAddress(req *utxo.TxAddressRequest) (*utxo.TxAddressResponse, error) {
	transaction, err := c.thirdPartClient.GetTransactionsByAddress(req.Address, strconv.Itoa(int(req.Page)), strconv.Itoa(int(req.Pagesize)))
	if err != nil {
		return &utxo.TxAddressResponse{
			Code: common2.ReturnCode_ERROR,
			Msg:  "get transaction list fail",
			Tx:   nil,
		}, err
	}
	var tx_list []*utxo.TxMessage
	for _, ttxs := range transaction.Txs {
		var from_addrs []*utxo.Address
		var to_addrs []*utxo.Address
		var value_list []*utxo.Value
		var direction int32
		for _, inputs := range ttxs.Inputs {
			from_addrs = append(from_addrs, &utxo.Address{Address: inputs.PrevOut.Addr})
		}
		tx_fee := ttxs.Fee
		for _, out := range ttxs.Out {
			to_addrs = append(to_addrs, &utxo.Address{Address: out.Addr})
			value_list = append(value_list, &utxo.Value{Value: out.Value.String()})
		}
		datetime := ttxs.Time.String()
		if strings.EqualFold(req.Address, from_addrs[0].Address) {
			direction = 0
		} else {
			direction = 1
		}
		tx := &utxo.TxMessage{
			Hash:     ttxs.Hash,
			Froms:    from_addrs,
			Tos:      to_addrs,
			Values:   value_list,
			Fee:      tx_fee.String(),
			Status:   utxo.TxStatus_Success,
			Type:     direction,
			Height:   ttxs.BlockHeight.String(),
			Datetime: datetime,
		}
		tx_list = append(tx_list, tx)
	}
	return &utxo.TxAddressResponse{
		Code: common2.ReturnCode_SUCCESS,
		Msg:  "get transaction list success",
		Tx:   tx_list,
	}, nil
}

func (c *ChainAdaptor) GetTxByHash(req *utxo.TxHashRequest) (*utxo.TxHashResponse, error) {
	transaction, err := c.thirdPartClient.GetTransactionsByHash(req.Hash)
	if err != nil {
		return &utxo.TxHashResponse{
			Code: common2.ReturnCode_ERROR,
			Msg:  "get transaction list fail",
			Tx:   nil,
		}, err
	}
	var from_addrs []*utxo.Address
	var to_addrs []*utxo.Address
	var value_list []*utxo.Value
	for _, inputs := range transaction.Inputs {
		from_addrs = append(from_addrs, &utxo.Address{Address: inputs.PrevOut.Addr})
	}
	tx_fee := transaction.Fee
	for _, out := range transaction.Out {
		to_addrs = append(to_addrs, &utxo.Address{Address: out.Addr})
		value_list = append(value_list, &utxo.Value{Value: out.Value.String()})
	}
	datetime := transaction.Time.String()
	txMsg := &utxo.TxMessage{
		Hash:     transaction.Hash,
		Froms:    from_addrs,
		Tos:      to_addrs,
		Values:   value_list,
		Fee:      tx_fee.String(),
		Status:   utxo.TxStatus_Success,
		Type:     0,
		Height:   transaction.BlockHeight.String(),
		Datetime: datetime,
	}
	return &utxo.TxHashResponse{
		Code: common2.ReturnCode_SUCCESS,
		Msg:  "get transaction success",
		Tx:   txMsg,
	}, nil
}

func (c *ChainAdaptor) CreateUnSignTransaction(req *utxo.UnSignTransactionRequest) (*utxo.UnSignTransactionResponse, error) {
	response := &utxo.UnSignTransactionResponse{
		Code:       common2.ReturnCode_ERROR,
		Msg:        "",
		TxData:     nil,
		SignHashes: nil,
	}
	if ok, msg := validateChainAndNetwork(req.Chain, ""); !ok {
		err := fmt.Errorf("CreateUnSignTransaction validateChainAndNetwork default failed: %s", msg)
		log.Error("err", err)
		response.Msg = err.Error()
		return nil, err
	}

	networkParams := &chaincfg.MainNetParams
	if req.Network != "mainnet" {
		networkParams = &chaincfg.SimNetParams
	}

	txHash, buf, err := c.CalcSignHashes(networkParams, req.Vin, req.Vout)
	if err != nil {
		log.Error("calc sign hashes fail", "err", err)
		return nil, err
	}
	response.TxData = buf
	response.SignHashes = txHash
	response.Code = common2.ReturnCode_SUCCESS
	response.Msg = "create un sign transaction success"
	return response, nil
}

func (c *ChainAdaptor) BuildSignedTransaction(req *utxo.SignedTransactionRequest) (*utxo.SignedTransactionResponse, error) {
	response := &utxo.SignedTransactionResponse{
		Code:         common2.ReturnCode_ERROR,
		Msg:          "",
		SignedTxData: nil,
		Hash:         nil,
	}
	if ok, msg := validateChainAndNetwork(req.Chain, ""); !ok {
		err := fmt.Errorf("BuildSignedTransaction validateChainAndNetwork default failed: %s", msg)
		log.Error("err", err)
		response.Msg = err.Error()
		return nil, err
	}

	networkParams := &chaincfg.MainNetParams
	if req.Network != "mainnet" {
		networkParams = &chaincfg.SimNetParams
	}

	var msgTx wire.MsgTx
	if err := msgTx.Deserialize(bytes.NewReader(req.TxData)); err != nil {
		log.Error("Create signed transaction msg tx deserialize", "err", err)
		return &utxo.SignedTransactionResponse{
			Code: common2.ReturnCode_ERROR,
			Msg:  err.Error(),
		}, err
	}

	if len(req.Signatures) != len(msgTx.TxIn) {
		err := errors.New("Signature number != Txin number")
		log.Error("CreateSignedTransaction invalid params", "err", err)
		return &utxo.SignedTransactionResponse{
			Code: common2.ReturnCode_ERROR,
			Msg:  err.Error(),
		}, err
	}

	if len(req.PublicKeys) != len(msgTx.TxIn) {
		err := errors.New("Pubkey number != Txin number")
		log.Error("CreateSignedTransaction invalid params", "err", err)
		return &utxo.SignedTransactionResponse{
			Code: common2.ReturnCode_ERROR,
			Msg:  err.Error(),
		}, err
	}

	for i, in := range msgTx.TxIn {
		btcecPub, err2 := btcec.ParsePubKey(req.PublicKeys[i])
		if err2 != nil {
			log.Error("CreateSignedTransaction ParsePubKey", "err", err2)
			return &utxo.SignedTransactionResponse{
				Code: common2.ReturnCode_ERROR,
				Msg:  err2.Error(),
			}, err2
		}
		var pkData []byte
		if btcec.IsCompressedPubKey(req.PublicKeys[i]) {
			pkData = btcecPub.SerializeCompressed()
		} else {
			pkData = btcecPub.SerializeUncompressed()
		}

		txHash := &in.PreviousOutPoint.Hash
		log.Info("Getting previous transaction",
			"txHash", txHash.String(),
			"index", in.PreviousOutPoint.Index)
		if txHash.IsEqual(&chainhash.Hash{}) {
			err2 := errors.New("invalid transaction hash (zero hash)")
			log.Error("CreateSignedTransaction invalid hash", "err", err2)
			return &utxo.SignedTransactionResponse{
				Code: common2.ReturnCode_ERROR,
				Msg:  err2.Error(),
			}, err2
		}

		preTx, err2 := c.btcClient.GetRawTransactionVerbose(txHash)
		if err2 != nil {
			errMsg := fmt.Sprintf("获取交易 %s 详情失败: %v", txHash.String(), err2)
			log.Error("CreateSignedTransaction GetRawTransactionVerbose",
				"txHash", txHash.String(),
				"err", err2)
			return &utxo.SignedTransactionResponse{
				Code: common2.ReturnCode_ERROR,
				Msg:  errMsg,
			}, err2
		}

		log.Info("CreateSignedTransaction ", "from address", preTx.Vout[in.PreviousOutPoint.Index].ScriptPubKey.Address)

		fromAddress, err2 := btcutil.DecodeAddress(preTx.Vout[in.PreviousOutPoint.Index].ScriptPubKey.Address, networkParams)
		if err2 != nil {
			log.Error("CreateSignedTransaction DecodeAddress", "err", err2)
			return &utxo.SignedTransactionResponse{
				Code: common2.ReturnCode_ERROR,
				Msg:  err2.Error(),
			}, err2
		}
		fromPkScript, err2 := txscript.PayToAddrScript(fromAddress)
		if err2 != nil {
			log.Error("CreateSignedTransaction PayToAddrScript", "err", err2)
			return &utxo.SignedTransactionResponse{
				Code: common2.ReturnCode_ERROR,
				Msg:  err2.Error(),
			}, err2
		}

		if len(req.Signatures[i]) < 65 {
			err2 = errors.New("Invalid signature length")
			return &utxo.SignedTransactionResponse{
				Code: common2.ReturnCode_ERROR,
				Msg:  err2.Error(),
			}, err2
		}

		sig := req.Signatures[i]

		builder := txscript.NewScriptBuilder()
		builder.AddData(sig)
		builder.AddData(pkData)
		sigScript, err := builder.Script()
		if err != nil {
			log.Error("create signed transaction new script builder", "err", err)
			return &utxo.SignedTransactionResponse{
				Code: common2.ReturnCode_ERROR,
				Msg:  err.Error(),
			}, err
		}

		msgTx.TxIn[i].SignatureScript = sigScript

		amount := btcToSatoshi(preTx.Vout[in.PreviousOutPoint.Index].Value).Int64()
		log.Info("CreateSignedTransaction ", "amount", preTx.Vout[in.PreviousOutPoint.Index].Value, "int amount", amount)

		vm, err := txscript.NewEngine(fromPkScript,
			&msgTx,
			i,
			txscript.StandardVerifyFlags,
			nil,
			nil,
			amount,
			nil)
		if err != nil {
			log.Error("create signed transaction newEngine", "err", err)
			return &utxo.SignedTransactionResponse{
				Code: common2.ReturnCode_ERROR,
				Msg:  err.Error(),
			}, err
		}

		if err := vm.Execute(); err != nil {
			log.Error("CreateSignedTransaction NewEngine Execute", "err", err)
			return &utxo.SignedTransactionResponse{
				Code: common2.ReturnCode_ERROR,
				Msg:  err.Error(),
			}, err
		}
	}
	// 序列化交易
	buf := bytes.NewBuffer(make([]byte, 0, msgTx.SerializeSize()))
	if err := msgTx.Serialize(buf); err != nil {
		log.Error("CreateSignedTransaction tx Serialize", "err", err)
		return &utxo.SignedTransactionResponse{
			Code: common2.ReturnCode_ERROR,
			Msg:  err.Error(),
		}, err
	}

	// 计算交易哈希
	hash := msgTx.TxHash()

	return &utxo.SignedTransactionResponse{
		Code:         common2.ReturnCode_SUCCESS,
		SignedTxData: buf.Bytes(),
		Hash:         (&hash).CloneBytes(),
	}, nil
}

func (c *ChainAdaptor) DecodeTransaction(req *utxo.DecodeTransactionRequest) (*utxo.DecodeTransactionResponse, error) {
	response := &utxo.DecodeTransactionResponse{
		Code: common2.ReturnCode_ERROR,
		Msg:  "",
	}
	if ok, msg := validateChainAndNetwork(req.Chain, ""); !ok {
		err := fmt.Errorf("CreateUnSignTransaction validateChainAndNetwork default failed: %s", msg)
		log.Error("err", err)
		response.Msg = err.Error()
		return nil, err
	}

	networkParams := &chaincfg.MainNetParams
	if req.Network != "mainnet" {
		networkParams = &chaincfg.SimNetParams
	}

	res, err := c.DecodeTx(networkParams, req.RawData, req.Vins, false)
	if err != nil {
		log.Info("decode tx fail", "err", err)
		return &utxo.DecodeTransactionResponse{
			Code: common2.ReturnCode_ERROR,
			Msg:  err.Error(),
		}, err
	}
	response.Code = common2.ReturnCode_SUCCESS
	response.Msg = "decode transaction response"
	response.SignHashes = res.SignHashes
	response.Status = utxo.TxStatus_Other
	response.Vins = res.Vins
	response.Vouts = res.Vouts
	response.CostFee = res.CostFee.String()
	return response, nil
}

func (c *ChainAdaptor) VerifySignedTransaction(req *utxo.VerifyTransactionRequest) (*utxo.VerifyTransactionResponse, error) {
	response := &utxo.VerifyTransactionResponse{
		Code:   common2.ReturnCode_ERROR,
		Msg:    "",
		Verify: false,
	}
	if ok, msg := validateChainAndNetwork(req.Chain, ""); !ok {
		err := fmt.Errorf("VerifySignedTransaction validateChainAndNetwork default failed: %s", msg)
		log.Error("err", err)
		response.Msg = err.Error()
		return nil, err
	}

	networkParams := &chaincfg.MainNetParams
	if req.Network != "mainnet" {
		networkParams = &chaincfg.SimNetParams
	}

	_, err := c.DecodeTx(networkParams, []byte(""), nil, true)
	if err != nil {
		err := fmt.Errorf("VerifySignedTransaction DecodeTx failed: %w", err)
		log.Error("err", err)
		response.Msg = err.Error()
		return nil, err
	}
	response.Code = common2.ReturnCode_SUCCESS
	response.Msg = "verify transaction success"
	response.Verify = true
	return response, nil
}

func (c *ChainAdaptor) CalcSignHashes(networkParams *chaincfg.Params, Vins []*utxo.Vin, Vouts []*utxo.Vout) ([][]byte, []byte, error) {
	if len(Vins) == 0 || len(Vouts) == 0 {
		return nil, nil, errors.New("invalid len in or out")
	}
	rawTx := wire.NewMsgTx(wire.TxVersion)
	for _, in := range Vins {
		utxoHash, err := chainhash.NewHashFromStr(in.Hash)
		if err != nil {
			log.Error("NewHashFromStr", "in.Hash", in.Hash, "err", err)
			return nil, nil, err
		}
		txIn := wire.NewTxIn(wire.NewOutPoint(utxoHash, in.Index), nil, nil)
		rawTx.AddTxIn(txIn)
	}
	for _, out := range Vouts {
		toAddress, err := btcutil.DecodeAddress(out.Address, networkParams)
		if err != nil {
			log.Error("DecodeAddress", "out.Address", out.Address, "err", err)
			return nil, nil, err
		}
		toPkScript, err := txscript.PayToAddrScript(toAddress)
		if err != nil {
			log.Error("PayToAddrScript", "out.Address", out.Address, "err", err)
			return nil, nil, err
		}
		rawTx.AddTxOut(wire.NewTxOut(out.Amount, toPkScript))
	}
	signHashes := make([][]byte, len(Vins))
	for i, in := range Vins {
		from := in.Address
		fromAddr, err := btcutil.DecodeAddress(from, networkParams)
		if err != nil {
			log.Error("decode address error", "from", from, "err", err)
			return nil, nil, err
		}
		fromPkScript, err := txscript.PayToAddrScript(fromAddr)
		if err != nil {
			log.Error("pay to addr script err", "err", err)
			return nil, nil, err
		}
		signHash, err := txscript.CalcSignatureHash(fromPkScript, txscript.SigHashAll, rawTx, i)
		if err != nil {
			log.Error("Calc signature hash error", "err", err)
			return nil, nil, err
		}
		signHashes[i] = signHash
	}

	txSize := rawTx.SerializeSize()
	var buf bytes.Buffer
	buf.Grow(txSize)

	if err := rawTx.Serialize(&buf); err != nil {
		log.Error("serialize transaction error",
			"err", err,
			"inputs", len(Vins),
			"outputs", len(Vouts))
		return nil, nil, err
	}
	return signHashes, buf.Bytes(), nil
}

func (c *ChainAdaptor) DecodeTx(networkParams *chaincfg.Params, txData []byte, vins []*utxo.Vin, sign bool) (*DecodeTxRes, error) {
	var msgTx wire.MsgTx
	err := msgTx.Deserialize(bytes.NewReader(txData))
	if err != nil {
		return nil, err
	}

	offline := true
	if len(vins) == 0 {
		offline = false
	}
	if offline && len(vins) != len(msgTx.TxIn) {
		return nil, errors.New("the length of deserialized tx's in differs from vin")
	}

	ins, totalAmountIn, err := c.DecodeVins(msgTx, offline, vins, sign)
	if err != nil {
		return nil, err
	}

	outs, totalAmountOut, err := c.DecodeVouts(msgTx)
	if err != nil {
		return nil, err
	}

	signHashes, _, err := c.CalcSignHashes(networkParams, ins, outs)
	if err != nil {
		return nil, err
	}
	res := DecodeTxRes{
		SignHashes: signHashes,
		Vins:       ins,
		Vouts:      outs,
		CostFee:    totalAmountIn.Sub(totalAmountIn, totalAmountOut),
	}
	if sign {
		res.Hash = msgTx.TxHash().String()
	}
	return &res, nil
}

func (c *ChainAdaptor) DecodeVins(msgTx wire.MsgTx, offline bool, vins []*utxo.Vin, sign bool) ([]*utxo.Vin, *big.Int, error) {
	ins := make([]*utxo.Vin, 0, len(msgTx.TxIn))
	totalAmountIn := big.NewInt(0)
	for index, in := range msgTx.TxIn {
		vin, err := c.GetVin(offline, vins, index, in)
		if err != nil {
			return nil, nil, err
		}

		if sign {
			err = c.VerifySign(vin, msgTx, index)
			if err != nil {
				return nil, nil, err
			}
		}
		totalAmountIn.Add(totalAmountIn, big.NewInt(vin.Amount))
		ins = append(ins, vin)
	}
	return ins, totalAmountIn, nil
}

func (c *ChainAdaptor) DecodeVouts(msgTx wire.MsgTx) ([]*utxo.Vout, *big.Int, error) {
	outs := make([]*utxo.Vout, 0, len(msgTx.TxOut))
	totalAmountOut := big.NewInt(0)
	for _, out := range msgTx.TxOut {
		var t utxo.Vout
		_, pubkeyAddrs, _, err := txscript.ExtractPkScriptAddrs(out.PkScript, &chaincfg.MainNetParams)
		if err != nil {
			return nil, nil, err
		}
		t.Address = pubkeyAddrs[0].EncodeAddress()
		t.Amount = out.Value
		totalAmountOut.Add(totalAmountOut, big.NewInt(t.Amount))
		outs = append(outs, &t)
	}
	return outs, totalAmountOut, nil
}

func (c *ChainAdaptor) GetVin(offline bool, vins []*utxo.Vin, index int, in *wire.TxIn) (*utxo.Vin, error) {
	var vin *utxo.Vin
	if offline {
		vin = vins[index]
	} else {
		preTx, err := c.btcClient.GetRawTransactionVerbose(&in.PreviousOutPoint.Hash)
		if err != nil {
			return nil, err
		}
		out := preTx.Vout[in.PreviousOutPoint.Index]
		vin = &utxo.Vin{
			Hash:    "",
			Index:   0,
			Amount:  btcToSatoshi(out.Value).Int64(),
			Address: out.ScriptPubKey.Address,
		}
	}
	vin.Hash = in.PreviousOutPoint.Hash.String()
	vin.Index = in.PreviousOutPoint.Index
	return vin, nil
}

func (c *ChainAdaptor) VerifySign(vin *utxo.Vin, msgTx wire.MsgTx, index int) error {
	fromAddress, err := btcutil.DecodeAddress(vin.Address, &chaincfg.MainNetParams)
	if err != nil {
		return err
	}

	fromPkScript, err := txscript.PayToAddrScript(fromAddress)
	if err != nil {
		return err
	}

	vm, err := txscript.NewEngine(fromPkScript, &msgTx, index, txscript.StandardVerifyFlags, nil, nil, vin.Amount, nil)
	if err != nil {
		return err
	}
	return vm.Execute()
}

func validateChainAndNetwork(chain, network string) (bool, string) {
	if chain != ChainName {
		return false, "invalid chain"
	}
	//if network != NetworkMainnet && network != NetworkTestnet {
	//	return false, "invalid network"
	//}
	return true, ""
}
