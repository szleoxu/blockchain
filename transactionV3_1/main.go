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
	"os"
	"encoding/hex"
	"strconv"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/ripemd160"
	"io/ioutil"
)

//挖矿难度
const targetBits = 18
//保存区块数据的桶名
const blocksBucket = "blocksBucket"
//链状态（用于存储未消费数据的桶名）
const utxoBucket = "chainstate"
//挖矿奖励货币数
const subsidy=50
//数据库文件名称
const dbFile="blockchain_%s.db"
//传世区块的内容
const genesisCoinBaseData = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
//地址产生算法的版本
const version = byte(0x00)
const addressChecksumLen = 4
const walletFile = "wallet_%s.dat"
//模拟节点的ID
const nodeID="3001"

var b58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

//当作钱包节点
func main() {
	//创建一个新的钱包
	/*wallets, _ := NewWallets(nodeID)
	address := wallets.CreateWallet()
	wallets.SaveToFile(nodeID)
	fmt.Printf("Your new address: %s\n", address)*/

	//创建创世块
	//createBlockchain("1DUqdGxeNrXfzQ9b4dfz9B2JvnyHna6wf3",nodeID)

	//币值转移
	/*send("13HvmLXtWCMcifD5dz3Lik94KrdqBhqLd8","1EzHQTq2PbkmfUfW2e4Q2TmmhiqDw6gPid",1,nodeID,false)
	send("18vHK6mLjzQKJCvaLfbt7cwajprjPZnGR1","14aHAPWSShPYAiNEWM2nUrXRg6nePo85D1",1,nodeID,false)*/

	///查看钱包公钥
	/*wallets, _ := NewWallets(nodeID)
	wallet:=wallets.GetWallet("1M9LNDuZsRQcky45Cx3MtPaftyAWWWQ61E")
	fmt.Println("pubkey:"+hex.EncodeToString(wallet.PublicKey))*/

	//获取钱包地址的帐户余额
	getBalance("13HvmLXtWCMcifD5dz3Lik94KrdqBhqLd8")
	getBalance("18vHK6mLjzQKJCvaLfbt7cwajprjPZnGR1")

	//遍历区块链中的所有区块数据
	//showBlock()

	//挖矿节点
	//StartServer(nodeID,"14aHAPWSShPYAiNEWM2nUrXRg6nePo85D1")
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
	//当前区块所在区块链的长度
	Height        int
}

//区块体(数据)
type BlockBody struct {
	//一个区块至少有一个交易
	Transactions  []*Transaction
}

//默克尔树的根节点
type MerkleTree struct {
	RootNode *MerkleNode
}

//默克尔树节点(左右节点类新为树节点本身)
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Data  []byte
}

//区块链
type BlockChain struct {
	//保存最新的区块哈希值
	tip []byte
	db  *bolt.DB
}

//未消费的链(与区块链的数据结构不同)
type UTXOSet struct {
	Blockchain *BlockChain
}

//证明工作量的数据结构
type ProofOfWork struct {
	block  *Block
	target *big.Int
}

//读取区块链数据的迭代器数据结构，用于一个个读取数据库数据（避免内存益出）
type BlockChainIterator struct {
	currentHash []byte
	db          *bolt.DB
}

type Transaction struct {
	ID   []byte
	Vin  []TXInput
	Vout []TXOutput
}

// 未消费的数据集合
type TXOutputs struct {
	Outputs []TXOutput
}

//交易记录输出结构
type TXOutput struct {
	//币值
	Value int
	//钱包公钥哈希值
	PubKeyHash []byte
}

//交易记录输入结构
type TXInput struct {
	//该输入对应的上一个交易记录的ID（一个交易里的输入会对应上一个交易里的输出）
	Txid []byte
	//该输入对应的另一个交易记录当中输出的索引（该索引可以告知是谁支付的）
	Vout int
	//一段向输出的ScriptPubKey字段中提供数据的脚本
	//ScriptSig string
	Signature []byte
	PubKey    []byte
}

type Wallet struct {
	PrivateKey ecdsa.PrivateKey
	PublicKey  []byte
}

type Wallets struct {
	Wallets map[string]*Wallet
}

//遍历区块链中的所有区块数据
func showBlock(){
	bc := NewBlockChain(nodeID)
	bci := bc.Iterator()
	for {
		//循环逐步迭代出每一个区块
		block := bci.Next()
		if block==nil{
			break
		}else{
			fmt.Printf("Prev. hash: %x\n", block.Head.PrevBlockHash)
			fmt.Printf("Hash: %x\n", block.Head.Hash)
			fmt.Println("Transactions")
			for _,tx:=range block.Body.Transactions{
				fmt.Println("ID:"+hex.EncodeToString(tx.ID))
				fmt.Println("Out")
				for i, out := range tx.Vout {
					fmt.Println("outIndex:"+strconv.Itoa(i))
					fmt.Println("PubKeyHash:"+hex.EncodeToString(out.PubKeyHash))
					fmt.Println("Value:"+strconv.Itoa(out.Value))
				}
				fmt.Println("In")
				for _, in := range tx.Vin {
					fmt.Println("Txid:"+hex.EncodeToString(in.Txid))
					fmt.Println("Vout:"+strconv.Itoa(in.Vout))
					fmt.Println("Signature:"+hex.EncodeToString(in.Signature))
					fmt.Println("PubKey:"+hex.EncodeToString(in.PubKey))
				}
			}
			fmt.Println()
		}
	}
}

//创建区块链
func CreateBlockChain(address , nodeID string) *BlockChain {
	dbFile := fmt.Sprintf(dbFile, nodeID)
	if dbExists(dbFile) {
		fmt.Println("Blockchain already exists.")
		os.Exit(1)
	}
	var tip []byte
	db, err := bolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		//获得币基交易数据结构
		cbtx := NewCoinbaseTX(address, genesisCoinBaseData)
		//创建创世块
		genesis := NewGenesisBlock(cbtx)

		b, err := tx.CreateBucket([]byte(blocksBucket))
		if err != nil {
			log.Panic(err)
		}
		//将创世块序列化保存到数据库中
		err = b.Put(genesis.Head.Hash, genesis.Serialize())
		if err != nil {
			log.Panic(err)
		}
		err = b.Put([]byte("l"), genesis.Head.Hash)
		if err != nil {
			log.Panic(err)
		}
		tip = genesis.Head.Hash
		return nil
	})

	if err != nil {
		log.Panic(err)
	}
	bc := BlockChain{tip, db}
	return &bc
}
//创建区块链(参数：钱包地址，第几个区块)
func createBlockchain(address, nodeID string){
	if !ValidateAddress(address) {
		log.Panic("ERROR: Address is not valid")
	}
	bc := CreateBlockChain(address,nodeID)
	defer bc.db.Close()

	UTXOSet := UTXOSet{bc}
	//从区块链当中获得所有的未消费输出,并单独保存在另一个桶内
	UTXOSet.Reindex()
	fmt.Println("Done!")
}

//获取钱包余额
func getBalance(address string) {
	//检查钱包地址是否正确
	if !ValidateAddress(address) {
		log.Panic("ERROR: Address is not valid")
	}
	bc := NewBlockChain(nodeID)
	UTXOSet := UTXOSet{bc}
	defer bc.db.Close()
	balance := 0
	pubKeyHash := Base58Decode([]byte(address))
	//实际的加密后的哈希公钥
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-addressChecksumLen]
	fmt.Println("钱包地址解析出的pubKeyHash:"+hex.EncodeToString(pubKeyHash))
	UTXOs := UTXOSet.FindUTXO(pubKeyHash)
	for _, out := range UTXOs {
		balance += out.Value
	}
	fmt.Printf("Balance of '%s': %d\n", address, balance)
}

//货币转移
func send(from,to string ,amount int, nodeID string, mineNow bool) {
	//拿到最新的区块哈希值，并返回区块链实例
	bc := NewBlockChain(nodeID)
	UTXOSet := UTXOSet{bc}
	defer bc.db.Close()
	wallets, err := NewWallets(nodeID)
	if err != nil {
		log.Panic(err)
	}
	wallet := wallets.GetWallet(from)
	//生成交易数据
	tx := NewUTXOTransaction(&wallet, to, amount, &UTXOSet)
	if mineNow {
		//生成一个币基交易
		cbTx := NewCoinbaseTX(from, "")
		txs := []*Transaction{cbTx, tx}
		//挖矿
		newBlock := bc.MineBlock(txs)
		//在一个新的区块被挖出来以后更新了 UTXO set(将新增的未消费的输出保存到UTXO set,且更新之前未消费的输出，消费了的就从UTXO set移除)。
		UTXOSet.Update(newBlock)
	} else {
		sendTx(knownNodes[0], tx)
	}
	fmt.Println("Success!")
}

//验证钱包地址是否真的有效send
func ValidateAddress(address string) bool {
	//base58解码。返回：Version+Public key hash+Checksum
	pubKeyHash := Base58Decode([]byte(address))
	//Checksum占整个字节的最后四个字节
	actualChecksum := pubKeyHash[len(pubKeyHash)-addressChecksumLen:]
	version := pubKeyHash[0]
	//实际的加密后的哈希公钥
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-addressChecksumLen]
	//预先将地址产生算法的版本给哈希，按算法生成checksum
	targetChecksum := checksum(append([]byte{version}, pubKeyHash...))
	//比较通过算法生成的checksum和解码获得的checksum是否一致
	return bytes.Compare(actualChecksum, targetChecksum) == 0
}

// 解码Base58的数据
func Base58Decode(input []byte) []byte {
	result := big.NewInt(0)
	zeroBytes := 0
	for b := range input {
		if b == 0x00 {
			zeroBytes++
		}
	}
	//截取了第一个字节数据
	payload := input[zeroBytes:]
	for _, b := range payload {
		charIndex := bytes.IndexByte(b58Alphabet, b)
		result.Mul(result, big.NewInt(58))
		result.Add(result, big.NewInt(int64(charIndex)))
	}
	decoded := result.Bytes()
	decoded = append(bytes.Repeat([]byte{byte(0x00)}, zeroBytes), decoded...)
	return decoded
}

//生成校验和(checksum),payload由地址产生算法的版本+公钥加密后的哈希公钥组成
func checksum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])
	//checksum是所得哈希值的前四个字节
	return secondSHA[:addressChecksumLen]
}

//创建一个新的节点
func NewMerkleNode(left, right *MerkleNode, data []byte) *MerkleNode {
	//树节点
	mNode := MerkleNode{}
	//当该节点的左右分支都为空时，表示是树的最低部，所以对单个交易记录进行哈希
	if left == nil && right == nil {
		hash := sha256.Sum256(data)
		mNode.Data = hash[:]
	} else {
		//当该节点的左右分支都不为空时，则将左右分支的数据合并，然后再进行哈希计算，最后保存为当前该节点根节点的值
		prevHashes := append(left.Data, right.Data...)
		hash := sha256.Sum256(prevHashes)
		mNode.Data = hash[:]
	}
	mNode.Left = left
	mNode.Right = right

	return &mNode
}

//将哈希后的交易记录生成一个默克尔树
func NewMerkleTree(data [][]byte) *MerkleTree {
	//用来保存同一个路径深度的树节点集合
	var nodes []MerkleNode
	//计算交易数量，如果交易数为奇数，则复制一个最后的交易数据，使其交易数为偶数
	if len(data)%2 != 0 {
		data = append(data, data[len(data)-1])
	}
	//将每个交易记录都生成一个树节点（也就是默克尔树的最低部）
	for _, datum := range data {
		//创建一个新的节点
		node := NewMerkleNode(nil, nil, datum)
		nodes = append(nodes, *node)
	}
	//将上面的交易节点集合生成一个默克尔树(可以画图演示，计算树的根节点计算次数确实为总交易数的一半)
	for i := 0; i < len(data)/2; i++ {
		var newLevel []MerkleNode
		//这个是将树的同一路径深度的节点进行上一层树节点的计算，直到计算到树的根节点
		for j := 0; j < len(nodes); j += 2 {
			//将相邻的两个节点最为新节点的左右分支，且计算出新节点根节点的哈希值
			node := NewMerkleNode(&nodes[j], &nodes[j+1], nil)
			newLevel = append(newLevel, *node)
		}
		//将新计算出来树的同一路径深度节点集合进行保存
		nodes = newLevel
	}
	//最终保存树的根节点
	mTree := MerkleTree{&nodes[0]}
	return &mTree
}


//挖矿创建新的区块
func NewBlock(transactions []*Transaction, prevBlockHash []byte, height int) *Block {
	//得到创建区块的信息
	blockHead := BlockHead{time.Now().Unix(), prevBlockHash, []byte{}, 0,height}
	blockBody := BlockBody{transactions}
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

//创建并初始化 UTXO set,从区块链当中获得所有的未消费输出,并保存到数据库中
func (u UTXOSet) Reindex() {
	db := u.Blockchain.db
	bucketName := []byte(utxoBucket)

	db.Update(func(tx *bolt.Tx) error {
		//删除原先的未消费数据，重新扫全链生成未消费的数据
		tx.DeleteBucket(bucketName)
		tx.CreateBucket(bucketName)
		return nil
	})
	//找出区块链中所有区块未消费的交易输出
	UTXO := u.Blockchain.FindUTXO()
	//将未消费的输出保存到
	db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		for txID, outs := range UTXO {
			key, _ := hex.DecodeString(txID)
			b.Put(key, outs.Serialize())
		}
		return nil
	})
}

// 交易输出序列化
func (outs TXOutputs) Serialize() []byte {
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(outs)
	if err != nil {
		log.Panic(err)
	}
	return buff.Bytes()
}

//将新的区块添加到区块链中（挖矿）
func (bc *BlockChain) MineBlock(transactions []*Transaction) *Block{
	//获取上一个区块
	var lastHash []byte
	var lastHeight int
	//验证交易签名有效，主要就是验证交易中输入对应的上一个交易的输出是否有所有权（防止用不是自己的货币进行交易）
	for _, tx := range transactions {
		if bc.VerifyTransaction(tx) != true {
			log.Panic("ERROR: Invalid transaction")
		}
	}
	err := bc.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(blocksBucket))
		lastHash = b.Get([]byte("l"))
		blockData := b.Get(lastHash)
		block := DeserializeBlock(blockData)
		lastHeight = block.Head.Height
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	//计算新的区块
	newBlock := NewBlock(transactions, lastHash,lastHeight+1)
	//挖矿成功后将新的区块保存到数据库中
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
	return newBlock
}

//记录创世块的内容，且上一个区块的哈希为空
func NewGenesisBlock(coinbase *Transaction) *Block {
	return NewBlock([]*Transaction{coinbase}, []byte{},0)
}


//拿到最新的区块哈希值，并返回区块链实例
func NewBlockChain(nodeID string) *BlockChain {
	dbFile := fmt.Sprintf(dbFile, nodeID)
	if dbExists(dbFile) == false {
		fmt.Println("No existing blockchain found. Create one first.")
		os.Exit(1)
	}
	var tip []byte
	//开启数据库连接
	db, _ := bolt.Open(dbFile, 0600, nil)
	//判断数据库的桶是否存在，如果存在则获取最新区块哈希值,如果不存在则创建创世块,并记录创世区块的哈希值
	db.Update(func(tx *bolt.Tx) error {
		//获取桶名称
		b := tx.Bucket([]byte(blocksBucket))
		tip = b.Get([]byte("l"))
		return nil
	})
	bc := BlockChain{tip, db}
	return &bc
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
			pow.block.Body.HashTransactions(),
			IntToHex(pow.block.Head.Timestamp),
			IntToHex(int64(targetBits)),
			IntToHex(int64(nonce)),
		},
		[]byte{},
	)
	return data
}

//将所有的交易记录生成一个默克尔树根哈希值
func (b *BlockBody) HashTransactions() []byte {
	//交易记录哈希后的集合
	var transactions [][]byte
	for _, tx := range b.Transactions {
		transactions = append(transactions, tx.Serialize())
	}
	//生成默克尔树并返回树根哈希
	mTree := NewMerkleTree(transactions)
	return mTree.RootNode.Data
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
	fmt.Printf("Mining the block containing \"%x\"\n", pow.block.Body.HashTransactions())
	maxNonce := math.MaxInt64
	//暴力计算符合条件的哈希值
	for nonce < maxNonce {
		data := pow.prepareData(nonce)
		//生成区块的哈希值
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

//币基交易(无需由对应的输出就能产生的特殊交易)
func NewCoinbaseTX(to, data string) *Transaction {
	//如果data为空，则随机生成一串字符串
	if data == "" {
		randData := make([]byte, 20)
		_, err := rand.Read(randData)
		if err != nil {
			log.Panic(err)
		}
		data = fmt.Sprintf("%x", randData)
	}
	txin := TXInput{[]byte{}, -1, nil, []byte(data)}
	txout := NewTXOutput(subsidy, to)
	tx := Transaction{nil, []TXInput{txin}, []TXOutput{*txout}}
	tx.ID = tx.Hash()
	return &tx
}

// 创建一个新的交易输出,address为接收货币的地址
func NewTXOutput(value int, address string) *TXOutput {
	txo := &TXOutput{value, nil}
	//将地址解析出哈希公钥，并保存到输出当中
	txo.Lock([]byte(address))
	return txo
}

//判断是否存在创世区块
func dbExists(dbFile string) bool {
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		return false
	}
	return true
}

//创建新的交易（使用未使用交易，建立新的区块交易，用于挖矿）
func NewUTXOTransaction(wallet *Wallet, to string, amount int, UTXOSet *UTXOSet) *Transaction {
	var inputs []TXInput
	var outputs []TXOutput
	//将钱包中的公钥进行两次哈希加密
	pubKeyHash := HashPubKey(wallet.PublicKey)
	//从未消费的链中找出未消费的由交易ID和输出索引组成的数组并且返回证明它们存有足够的币值
	acc, validOutputs := UTXOSet.FindSpendableOutputs(pubKeyHash, amount)
	if acc < amount {
		log.Panic("ERROR: Not enough funds")
	}
	//生成新区块交易中需要的输入数组.validOutputs由交易id和索引组成的map类型的数组,交易id为map的key
	for txid, outs := range validOutputs {
		txID,_ := hex.DecodeString(txid)
		for _, out := range outs {
			input := TXInput{txID, out, nil, wallet.PublicKey}
			inputs = append(inputs, input)
		}
	}
	//生成新区块交易中需要的输出数组(创建一个新的交易输出)
	from := fmt.Sprintf("%s", wallet.GetAddress())
	outputs = append(outputs, *NewTXOutput(amount, to))
	//如果未消费的币数大于消费的币数，那么剩下的币数返回给支付方的钱包地址
	if acc > amount {
		outputs = append(outputs, *NewTXOutput(acc-amount, from)) // 货币是不能分割的，只能通过这种找零的方式，重新生成一个输出返还给支付者
	}
	//生成新的交易数据结构，用于挖矿
	tx := Transaction{nil, inputs, outputs}
	//将Transaction的数据结构（此时的ID为空）序列化,然后给Transaction的自身ID赋值
	tx.ID = tx.Hash()
	//对新建的交易进行签名（钱包私钥签名），确保不能对未签名的交易记录进行挖矿
	UTXOSet.Blockchain.SignTransaction(&tx, wallet.PrivateKey)
	return &tx
}

//通过地址获得钱包数据结构的数据
func (ws Wallets) GetWallet(address string) Wallet {
	return *ws.Wallets[address]
}

//如果钱包文件存在，则实例化生成一个钱包数据结构的实例
func NewWallets(nodeID string) (*Wallets, error) {
	wallets := Wallets{}
	wallets.Wallets = make(map[string]*Wallet)

	err := wallets.LoadFromFile(nodeID)

	return &wallets, err
}

//从钱包文件中加载钱包
func (ws *Wallets) LoadFromFile(nodeID string) error {
	walletFile := fmt.Sprintf(walletFile, nodeID)
	if _, err := os.Stat(walletFile); os.IsNotExist(err) {
		return err
	}
	fileContent, err := ioutil.ReadFile(walletFile)
	if err != nil {
		log.Panic(err)
	}
	var wallets Wallets
	gob.Register(elliptic.P256())
	decoder := gob.NewDecoder(bytes.NewReader(fileContent))
	err = decoder.Decode(&wallets)
	if err != nil {
		log.Panic(err)
	}
	ws.Wallets = wallets.Wallets
	return nil
}

// 保存钱包数据的文件
func (ws Wallets) SaveToFile(nodeID string) {
	var content bytes.Buffer
	walletFile := fmt.Sprintf(walletFile, nodeID)
	gob.Register(elliptic.P256())
	encoder := gob.NewEncoder(&content)
	err := encoder.Encode(ws)
	if err != nil {
		log.Panic(err)
	}
	err = ioutil.WriteFile(walletFile, content.Bytes(), 0644)
	if err != nil {
		log.Panic(err)
	}
}

//找出可以消费的币值和交易ID对应的输出索引（所有的未消费输出并且确保它们存有足够的币值）
func (u UTXOSet) FindSpendableOutputs(pubkeyHash []byte, amount int) (int, map[string][]int) {
	unspentOutputs := make(map[string][]int)
	accumulated := 0
	db := u.Blockchain.db
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(utxoBucket))
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			txID := hex.EncodeToString(k)
			outs := DeserializeOutputs(v)
			for outIdx, out := range outs.Outputs {
				//在输出中找到和加密后的公钥哈希(公钥哈希来自解析钱包地址)匹配的交易记录
				if out.IsLockedWithKey(pubkeyHash) && accumulated < amount {
					accumulated += out.Value
					unspentOutputs[txID] = append(unspentOutputs[txID], outIdx)
				}
			}
		}
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	return accumulated, unspentOutputs
}

//判断该交易是不是币基交易
func (tx Transaction) IsCoinbase() bool {
	return len(tx.Vin) == 1 && len(tx.Vin[0].Txid) == 0 && tx.Vin[0].Vout == -1
}

//未消费输出的交易记录(公钥加密后的钱包地址)
func (u UTXOSet) FindUTXO(pubKeyHash []byte) []TXOutput {
	var UTXOs []TXOutput
	db := u.Blockchain.db
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(utxoBucket))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			outs := DeserializeOutputs(v)
			for _, out := range outs.Outputs {
				if out.IsLockedWithKey(pubKeyHash) {
					UTXOs = append(UTXOs, out)
				}
			}
		}
		return nil
	})
	return UTXOs
}

//反序列化返回交易记录输出TXOutputs
func DeserializeOutputs(data []byte) TXOutputs {
	var outputs TXOutputs

	dec := gob.NewDecoder(bytes.NewReader(data))
	err := dec.Decode(&outputs)
	if err != nil {
		log.Panic(err)
	}

	return outputs
}

//将新区块中输入对应的上一个交易中的未消费输出清除掉，并且把新区块的交易输出都保存到未消费交易输出链
func (u UTXOSet) Update(block *Block) {
	db := u.Blockchain.db
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(utxoBucket))
		//遍历最新区块中所有的交易记录
		for _, tx := range block.Body.Transactions {
			//币基交易找不到对应的上一个未消费输出
			if tx.IsCoinbase() == false {
				//遍历新区块中的所有交易输入
				for _, vin := range tx.Vin {
					//需要更新的未消费的输出集合
					updatedOuts := TXOutputs{}
					//从未消费的链中找到已经消费的交易id对应的输出
					outsBytes := b.Get(vin.Txid)
					outs := DeserializeOutputs(outsBytes)
					for outIdx, out := range outs.Outputs {
						//如果新区块输入中的上一个输出的索引，与当前其它索引的输出不一致，表明这些索引的输出是未消费过的
						if outIdx != vin.Vout {
							//所以重新将那些未消费的记录保存
							updatedOuts.Outputs = append(updatedOuts.Outputs, out)
						}
					}
					//如果没有保存任何一条未消费输出，表明该交易ID对应的交易记录都被消费了，可以直接删除这个交易记录对应的所有输出
					if len(updatedOuts.Outputs) == 0 {
						err := b.Delete(vin.Txid)
						if err != nil {
							log.Panic(err)
						}
					} else {
						//更新（覆盖）原先该交易ID对应的交易输出
						err := b.Put(vin.Txid, updatedOuts.Serialize())
						if err != nil {
							log.Panic(err)
						}
					}
				}
			}
			newOutputs := TXOutputs{}
			//新区块的输出都是未消费输出
			for _, out := range tx.Vout {
				newOutputs.Outputs = append(newOutputs.Outputs, out)
			}
			//将新的未消费交易输出保存到未消费交易输出链中
			err := b.Put(tx.ID, newOutputs.Serialize())
			if err != nil {
				log.Panic(err)
			}
		}
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
}

//新建一个钱包
func NewWallet() *Wallet {
	private, public := newKeyPair()
	wallet := Wallet{private, public}
	return &wallet
}

//生成钱包的一对公私钥
func newKeyPair() (ecdsa.PrivateKey, []byte) {
	curve := elliptic.P256()
	private, _ := ecdsa.GenerateKey(curve, rand.Reader)
	pubKey := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)

	return *private, pubKey
}

//生成钱包地址，并保存到钱包结构中
func (ws *Wallets) CreateWallet() string {
	wallet := NewWallet()
	address := fmt.Sprintf("%s", wallet.GetAddress())
	ws.Wallets[address] = wallet
	return address
}

//获得钱包地址(钱包地址的生成过程)
func (w Wallet) GetAddress() []byte {
	//将钱包公钥进行两次哈希加密
	pubKeyHash := HashPubKey(w.PublicKey)
	//地址产生算法的版本和加密后的哈希公钥进行组合
	versionedPayload := append([]byte{version}, pubKeyHash...)
	//然后将versionedPayload进行两次的SHA256哈希加密。checksum是所得哈希值的前四个字节
	checksum := checksum(versionedPayload)
	//又将versionedPayload和checksum组合
	fullPayload := append(versionedPayload, checksum...)
	//最后将fullPayload进行base58加密获得钱包地址
	address := Base58Encode(fullPayload)
	return address
}

//将公钥进行两次哈希计算
func HashPubKey(pubKey []byte) []byte {
	publicSHA256 := sha256.Sum256(pubKey)
	RIPEMD160Hasher := ripemd160.New()
	RIPEMD160Hasher.Write(publicSHA256[:])
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)
	return publicRIPEMD160
}

//检查一个输入是否可以用一个特定的密钥去解锁一个输出
func (in *TXInput) UsesKey(pubKeyHash []byte) bool {
	//将公钥进行两次哈希计算
	lockingHash := HashPubKey(in.PubKey)
	return bytes.Compare(lockingHash, pubKeyHash) == 0
}

//将接收货币新建的输出进行锁定。（这里的锁定就是通过接收者的钱包地址解析出加密后的哈希公钥，并保存到输出的哈希公钥.PS:没有消费的输出就是帐户的余额）
func (out *TXOutput) Lock(address []byte) {
	pubKeyHash := Base58Decode(address)
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-4]
	out.PubKeyHash = pubKeyHash
}

//检查提供的公钥哈希是否是用于去锁定输出
func (out *TXOutput) IsLockedWithKey(pubKeyHash []byte) bool {
	return bytes.Compare(out.PubKeyHash, pubKeyHash) == 0
}

//对新增交易的输入赋值签名
func (tx *Transaction) Sign(privKey ecdsa.PrivateKey, prevTXs map[string]Transaction) {
	if tx.IsCoinbase() {
		return
	}
	//截取过的交易记录拷贝会被签名，并不完整的交易记录签名(这个赋值的交易记录中，输入中没有钱包里的公钥，其它内容都一样)
	txCopy := tx.TrimmedCopy()
	//对新的交易中每个输入的签名赋值
	for inID, vin := range txCopy.Vin {
		//得到交易记录
		prevTx := prevTXs[hex.EncodeToString(vin.Txid)]
		//其实txCopy中的Signature已经是nil了，但这里只是再次确认一下
		txCopy.Vin[inID].Signature = nil
		//这里签名的数据其中公钥保存的是公钥加密后的哈希公钥（最初生产的输入保存的是为加密的钱包公钥）
		txCopy.Vin[inID].PubKey = prevTx.Vout[vin.Vout].PubKeyHash
		//因为重新设置了输入中的公钥值，所以重新对副本中的交易ID重新进行哈希计算
		txCopy.ID = txCopy.Hash()
		//上面给公钥赋值哈希公钥后，对整个交易进行哈希计算，再赋值给ID（而这个ID就是我们所说的交易ID），最终重新给公钥赋值为空
		txCopy.Vin[inID].PubKey = nil
		//其实最终就是对交易数据哈希计算后的交易ID进行签名
		r, s, _ := ecdsa.Sign(rand.Reader, &privKey, txCopy.ID)
		signature := append(r.Bytes(), s.Bytes()...)
		//通过上面的签名算法，最终给交易中的输入赋值签名的值
		tx.Vin[inID].Signature = signature
	}
}

// 返回整个交易生成的哈希值
func (tx *Transaction) Hash() []byte {
	var hash [32]byte
	txCopy := *tx
	txCopy.ID = []byte{}
	hash = sha256.Sum256(txCopy.Serialize())
	return hash[:]
}

// 将交易数据序列化
func (tx Transaction) Serialize() []byte {
	var encoded bytes.Buffer
	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(tx)
	if err != nil {
		log.Panic(err)
	}
	return encoded.Bytes()
}

//截取现有的交易数据，将其中的输入的公钥设置为nil，并将新生成的这个交易数据进行签名
func (tx *Transaction) TrimmedCopy() Transaction {
	var inputs []TXInput
	var outputs []TXOutput
	for _, vin := range tx.Vin {
		inputs = append(inputs, TXInput{vin.Txid, vin.Vout, nil, nil})
	}
	for _, vout := range tx.Vout {
		outputs = append(outputs, TXOutput{vout.Value, vout.PubKeyHash})
	}
	txCopy := Transaction{tx.ID, inputs, outputs}
	return txCopy
}

//验证当前交易是不是和上一个交易相关
func (tx *Transaction) Verify(prevTXs map[string]Transaction) bool {
	//先截取当前交易的副本（也就是输入中的公钥未nil）
	txCopy := tx.TrimmedCopy()
	curve := elliptic.P256()
	for inID, vin := range tx.Vin {
		//找到新增交易输出中对应的那些交易ID对应的交易记录
		prevTx := prevTXs[hex.EncodeToString(vin.Txid)]
		//将副本中记录，按照签名时的副本流程再走一遍。然后将新增交易输入中的签名,再获取到对应的上一个交易记录且进行哈希计算，再用输入中的公钥去验证哈希计算
		txCopy.Vin[inID].Signature = nil
		txCopy.Vin[inID].PubKey = prevTx.Vout[vin.Vout].PubKeyHash
		txCopy.ID = txCopy.Hash()
		txCopy.Vin[inID].PubKey = nil
		r := big.Int{}
		s := big.Int{}
		sigLen := len(vin.Signature)
		r.SetBytes(vin.Signature[:(sigLen / 2)])
		s.SetBytes(vin.Signature[(sigLen / 2):])
		x := big.Int{}
		y := big.Int{}
		keyLen := len(vin.PubKey)
		x.SetBytes(vin.PubKey[:(keyLen / 2)])
		y.SetBytes(vin.PubKey[(keyLen / 2):])
		rawPubKey := ecdsa.PublicKey{curve, &x, &y}
		if ecdsa.Verify(&rawPubKey, txCopy.ID, &r, &s) == false {
			return false
		}
	}
	return true
}

//通过交易ID找到区块中指定的交易记录
func (bc *BlockChain) FindTransaction(ID []byte) (Transaction, error) {
	bci := bc.Iterator()
	for {
		block := bci.Next()
		for _, tx := range block.Body.Transactions {
			if bytes.Compare(tx.ID, ID) == 0 {
				return *tx, nil
			}
		}
		if len(block.Head.PrevBlockHash) == 0 {
			break
		}
	}
	return Transaction{}, errors.New("Transaction is not found")
}

//签名新增的交易
func (bc *BlockChain) SignTransaction(tx *Transaction, privKey ecdsa.PrivateKey) {
	prevTXs := make(map[string]Transaction)
	for _, vin := range tx.Vin {
		//找新增交易输入中的上一个交易id(也就是那些还没消费的输出)
		prevTX, _ := bc.FindTransaction(vin.Txid)
		prevTXs[hex.EncodeToString(prevTX.ID)] = prevTX
	}
	//对新增交易对应的上一个交易进行签名,用来表示对上一个未消费的交易拥有归属权（属于自己的钱包余额）
	tx.Sign(privKey, prevTXs)
}

//验证交易是否有效
func (bc *BlockChain) VerifyTransaction(tx *Transaction) bool {
	//如果是币基交易，则无需验证是否对应上一个交易的输出。因为币基交易根本就没有
	if tx.IsCoinbase() {
		return true
	}
	//相对于当前新增的交易对应的上一个交易记录（也就是未消费的交易记录）
	prevTXs := make(map[string]Transaction)
	for _, vin := range tx.Vin {
		prevTX, _ := bc.FindTransaction(vin.Txid)
		prevTXs[hex.EncodeToString(prevTX.ID)] = prevTX
	}
	//验证支付方发起的支付，是否对对应的上一个未消费的记录有所有权
	return tx.Verify(prevTXs)
}

//将字节数组进行base58加密
func Base58Encode(input []byte) []byte {
	var result []byte
	x := big.NewInt(0).SetBytes(input)
	base := big.NewInt(int64(len(b58Alphabet)))
	zero := big.NewInt(0)
	mod := &big.Int{}
	for x.Cmp(zero) != 0 {
		x.DivMod(x, base, mod)
		result = append(result, b58Alphabet[mod.Int64()])
	}
	//将字节数组中的数据颠倒过来
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	for b := range input {
		if b == 0x00 {
			result = append([]byte{b58Alphabet[0]}, result...)
		} else {
			break
		}
	}
	return result
}