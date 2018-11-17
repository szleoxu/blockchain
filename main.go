package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"github.com/boltdb/bolt"
	"log"
	"math"
	"math/big"
	"time"
	"strconv"
)

//挖矿难度
const targetBits = 14
//保存区块元数据的桶名
const blocksBucket = "blocksBucket"

func main() {

	bc := NewBlockChain()
	//bc.AddBlock("Send 1 BTC to ZJC")
	//bc.AddBlock("ZJC Send 20 BTC to Leo")
	bci := bc.Iterator()
	for {
		//循环逐步迭代出每一个区块
		block := bci.Next()
		if block==nil{
			break
		}else{
			fmt.Printf("Prev. hash: %x\n", block.Head.PrevBlockHash)
			fmt.Printf("Data: %s\n", block.Body.Data)
			fmt.Printf("Hash: %x\n", block.Head.Hash)
			fmt.Printf("Nonce: %d\n", block.Head.Nonce)
			pow := NewProofOfWork(block)
			//验证工作证明是否有效
			fmt.Printf("PoW: %s\n", strconv.FormatBool(pow.Validate()))
			fmt.Println()
		}
	}

}

//定义一个区块区块数据结构
type Block struct {
	Head BlockHead
	Body BlockBody
}

//区块头
type BlockHead struct {
	Timestamp     int64
	PrevBlockHash []byte
	Hash          []byte
	Nonce         int
}

//区块体(数据)
type BlockBody struct {
	Data []byte
}


//挖矿创建新的区块
func NewBlock(data string, prevBlockHash []byte) *Block {
	//得到创建区块的信息
	blockHead := BlockHead{time.Now().Unix(), prevBlockHash, []byte{}, 0}
	blockBody := BlockBody{[]byte(data)}
	block := &Block{blockHead, blockBody}
	//初始化挖矿前的目标哈希值
	pow := NewProofOfWork(block)
	//挖矿计算新区块的哈希值
	nonce, hash := pow.Run()
	//将计算得到的新区块哈希值和计数器保存到新区块中
	block.Head.Hash = hash[:]
	block.Head.Nonce = nonce
	return block
}

//区块链
type BlockChain struct {
	tip []byte
	db  *bolt.DB
}

//将新的区块添加到区块链中
func (bc *BlockChain) AddBlock(data string) {
	//获取上一个区块
	var lastHash []byte
	err := bc.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		lastHash = b.Get([]byte("l"))
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	//计算新的区块
	newBlock := NewBlock(data, lastHash)

	err = bc.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		err := b.Put(newBlock.Head.Hash, newBlock.Serialize())
		if err != nil {
			log.Panic(err)
		}
		//将最新的区块哈希值保存在"l"中
		err = b.Put([]byte("l"), newBlock.Head.Hash)
		bc.tip = newBlock.Head.Hash
		return nil
	})

}

//记录创世块的内容，且上一个区块的哈希为空
func NewGenesisBlock() *Block {
	return NewBlock("Genesis Block", []byte{})
}

//将创世块的内容添加到空的区块链中,如果有创世块则拿到最新的区块哈希值，并返回区块链实例
func NewBlockChain() *BlockChain {
	var tip []byte
	//开启数据库连接
	db, _ := bolt.Open("blockDB", 0600, nil)
	//判断数据库的桶是否存在，如果存在则获取最新区块哈希值,如果不存在则创建创世块,并记录创世区块的哈希值
	db.Update(func(tx *bolt.Tx) error {
		//获取桶名称
		b := tx.Bucket([]byte(blocksBucket))
		if b == nil {
			genesis := NewGenesisBlock()
			b, _ := tx.CreateBucket([]byte(blocksBucket))
			b.Put(genesis.Head.Hash, genesis.Serialize())
			b.Put([]byte("l"), genesis.Head.Hash)
			tip = genesis.Head.Hash
		} else {
			tip = b.Get([]byte("l"))
		}
		return nil
	})
	bc := BlockChain{tip, db}
	return &bc
}

//证明工作量的数据结构
type ProofOfWork struct {
	block  *Block
	target *big.Int
}

//工作量证明的目标值
func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	//挖矿难度系数越高，则左位移越小，目标值越小，计算的符合条件的哈希值越少，则挖矿难度越大
	target.Lsh(target, uint(256-targetBits))
	pow := &ProofOfWork{b, target}
	return pow
}

//准备需要计算哈希值的数据
func (pow *ProofOfWork) prepareData(nonce int) []byte {
	data := bytes.Join(
		[][]byte{
			pow.block.Head.PrevBlockHash,
			pow.block.Body.Data,
			IntToHex(pow.block.Head.Timestamp),
			IntToHex(int64(targetBits)),
			IntToHex(int64(nonce)),
		},
		[]byte{},
	)
	return data
}

//将整型数据转换成字节数据
func IntToHex(num int64) []byte {
	buff := new(bytes.Buffer)
	err := binary.Write(buff, binary.BigEndian, num)
	if err != nil {
		log.Panic(err)
	}
	return buff.Bytes()
}

//开始挖矿（计算新区块小于目标哈希的哈希值）
func (pow *ProofOfWork) Run() (int, []byte) {
	var hashInt big.Int
	var hash [32]byte
	nonce := 0
	fmt.Printf("Mining the block containing \"%s\"\n", pow.block.Body.Data)
	maxNonce := math.MaxInt64
	//暴力计算符合条件的哈希值
	for nonce < maxNonce {
		data := pow.prepareData(nonce)
		hash = sha256.Sum256(data)
		fmt.Printf("\r%x", hash)
		hashInt.SetBytes(hash[:])
		if hashInt.Cmp(pow.target) == -1 {
			break
		} else {
			nonce++
		}
	}
	fmt.Print("\n\n")

	return nonce, hash[:]
}

//验证工作证明
func (pow *ProofOfWork) Validate() bool {
	var hashInt big.Int
	data := pow.prepareData(pow.block.Head.Nonce)
	hash := sha256.Sum256(data)
	//字节转整型
	hashInt.SetBytes(hash[:])
	isValid := hashInt.Cmp(pow.target) == -1
	return isValid
}

//将要保存的区块数据序列化
func (b *Block) Serialize() []byte {
	var result bytes.Buffer
	encoder := gob.NewEncoder(&result)
	encoder.Encode(b)
	return result.Bytes()
}

//将存储在数据库中的数据反序列化，得到区块结构数据
func DeserializeBlock(d []byte) *Block {
	var block Block
	decoder := gob.NewDecoder(bytes.NewReader(d))
	decoder.Decode(&block)
	return &block
}

//读取区块链数据的迭代器数据结构，用于一个个读取数据库数据（避免内存益出）
type BlockChainIterator struct {
	currentHash []byte
	db          *bolt.DB
}

//以迭代器的形式获取区块链中的数据,并返回迭代器
func (bc *BlockChain) Iterator() *BlockChainIterator {
	bci := &BlockChainIterator{bc.tip, bc.db}
	return bci
}

//获取当前哈希值对应的区块，并且迭代器保存对应区块的上一个区块的哈希值
func (i *BlockChainIterator) Next() *Block {
	var block *Block
	i.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		encodedBlock := b.Get(i.currentHash)
		if len(encodedBlock)!=0{
			block = DeserializeBlock(encodedBlock)
		}
		return nil
	})
	if block==nil{
		return nil
	}else{
		i.currentHash = block.Head.PrevBlockHash
		return block
	}
}
