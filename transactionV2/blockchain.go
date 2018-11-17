package main

import "encoding/hex"

//找出区块链中所有区块的交易输出并且返回未消费的交易输出
func (bc *BlockChain) FindUTXO() map[string]TXOutputs {
	//未消费的交易输出集合
	UTXO := make(map[string]TXOutputs)
	//已经消费交易对应的支付交易数据集合（保存的都是已经支付了的交易记录）
	spentTXOs := make(map[string][]int)
	bci := bc.Iterator()
	for {
		block := bci.Next()
		for _, tx := range block.Body.Transactions {
			txID := hex.EncodeToString(tx.ID)
		Outputs:
			for outIdx, out := range tx.Vout {
				// 判断是否已经消费了输出
				if spentTXOs[txID] != nil {
					for _, spentOutIdx := range spentTXOs[txID] {
						if spentOutIdx == outIdx {
							continue Outputs
						}
					}
				}
				outs := UTXO[txID]
				outs.Outputs = append(outs.Outputs, out)
				UTXO[txID] = outs
			}
			if tx.IsCoinbase() == false {
				for _, in := range tx.Vin {
					inTxID := hex.EncodeToString(in.Txid)
					spentTXOs[inTxID] = append(spentTXOs[inTxID], in.Vout)
				}
			}
		}
		if len(block.Head.PrevBlockHash) == 0 {
			break
		}
	}
	return UTXO
}