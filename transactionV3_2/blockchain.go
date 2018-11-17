package main

import (
	"encoding/hex"
	"log"
	"github.com/boltdb/bolt"
	"errors"
)

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

// AddBlock saves the block into the blockchain
func (bc *BlockChain) AddBlock(block *Block) {
	err := bc.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		blockInDb := b.Get(block.Head.Hash)

		if blockInDb != nil {
			return nil
		}

		blockData := block.Serialize()
		err := b.Put(block.Head.Hash, blockData)
		if err != nil {
			log.Panic(err)
		}

		lastHash := b.Get([]byte("l"))
		lastBlockData := b.Get(lastHash)
		lastBlock := DeserializeBlock(lastBlockData)

		if block.Head.Height > lastBlock.Head.Height {
			err = b.Put([]byte("l"), block.Head.Hash)
			if err != nil {
				log.Panic(err)
			}
			bc.tip = block.Head.Hash
		}

		return nil
	})
	if err != nil {
		log.Panic(err)
	}
}

// GetBestHeight returns the height of the latest block
func (bc *BlockChain) GetBestHeight() int {
	var lastBlock Block

	err := bc.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		lastHash := b.Get([]byte("l"))
		blockData := b.Get(lastHash)
		lastBlock = *DeserializeBlock(blockData)

		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	return lastBlock.Head.Height
}

// GetBlockHashes returns a list of hashes of all the blocks in the chain
func (bc *BlockChain) GetBlockHashes() [][]byte {
	var blocks [][]byte
	bci := bc.Iterator()

	for {
		block := bci.Next()

		blocks = append(blocks, block.Head.Hash)

		if len(block.Head.PrevBlockHash) == 0 {
			break
		}
	}
	return blocks
}

// GetBlock finds a block by its hash and returns it
func (bc *BlockChain) GetBlock(blockHash []byte) (Block, error) {
	var block Block

	err := bc.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))

		blockData := b.Get(blockHash)

		if blockData == nil {
			return errors.New("Block is not found.")
		}

		block = *DeserializeBlock(blockData)

		return nil
	})
	if err != nil {
		return block, err
	}

	return block, nil
}
