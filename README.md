# block_address 地址私钥创建

  public static BlockAddress createAddress(List<String> mnemonic, String path) throws MnemonicException.MnemonicLengthException, ServiceException {

  System.out.println(path);
        String[] pathArray = path.split("/");
        long creationTimeSeconds = System.currentTimeMillis() / 1000;
        SecureRandom secureRandom = new SecureRandom();
        byte[] entropy = new byte[DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS / 8];
        secureRandom.nextBytes(entropy);
        DeterministicSeed ds = new DeterministicSeed(mnemonic, null, "", creationTimeSeconds);

        //根私钥
        byte[] seedBytes = ds.getSeedBytes();

        if (seedBytes == null) throw new ServiceException("根私钥异常");
        DeterministicKey dkKey = HDKeyDerivation.createMasterPrivateKey(seedBytes);
        for (int i = 1; i < pathArray.length; i++) {
            ChildNumber childNumber;
            if (pathArray[i].endsWith("'")) {
                int number = Integer.parseInt(pathArray[i].substring(0,
                        pathArray[i].length() - 1));
                childNumber = new ChildNumber(number, true);
            } else {
                int number = Integer.parseInt(pathArray[i]);
                childNumber = new ChildNumber(number, false);
            }
            dkKey = HDKeyDerivation.deriveChildKey(dkKey, childNumber);
        }
        ECKeyPair keyPair = ECKeyPair.create(dkKey.getPrivKeyBytes());
        BlockAddress blockAddress = new BlockAddress();

        //通过公钥生成钱包地址
        String address = "0x" + Keys.getAddress(keyPair.getPublicKey());
        //私钥
        String privateKey = keyPair.getPrivateKey().toString(16);
        blockAddress.setPrivateKey(privateKey);
        //公钥
        String publicKey = keyPair.getPublicKey().toString(16);
        blockAddress.setPublicKey(publicKey);
        blockAddress.setAddress(address);
        System.out.println(address);
        if (privateKey.length() < 64) {
            for (int i = 0; i < 64 - privateKey.length(); i++) {
                privateKey = 0 + privateKey;
            }
        }
        return blockAddress;
    }
                                  
                                  
         public static BlockAddress createAddress() throws MnemonicException.MnemonicLengthException, ServiceException {
        String path = "m/44'/60'/0'/0/0";
        String[] pathArray = path.split("/");
        long creationTimeSeconds = System.currentTimeMillis() / 1000;
        SecureRandom secureRandom = new SecureRandom();
        byte[] entropy = new byte[DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS / 8];
        secureRandom.nextBytes(entropy);

        List<String> mnemonic = MnemonicCode.INSTANCE.toMnemonic(entropy);
        DeterministicSeed ds = new DeterministicSeed(mnemonic, null, "", creationTimeSeconds);

        byte[] seedBytes = ds.getSeedBytes();

        if (seedBytes == null) throw new ServiceException("根私钥异常");
        DeterministicKey dkKey = HDKeyDerivation.createMasterPrivateKey(seedBytes);
        for (int i = 1; i < pathArray.length; i++) {
            ChildNumber childNumber;
            if (pathArray[i].endsWith("'")) {
                int number = Integer.parseInt(pathArray[i].substring(0,
                        pathArray[i].length() - 1));
                childNumber = new ChildNumber(number, true);
            } else {
                int number = Integer.parseInt(pathArray[i]);
                childNumber = new ChildNumber(number, false);
            }
            dkKey = HDKeyDerivation.deriveChildKey(dkKey, childNumber);
        }
        ECKeyPair keyPair = ECKeyPair.create(dkKey.getPrivKeyBytes());
        BlockAddress blockAddress = new BlockAddress();

        //通过公钥生成钱包地址
        String address = "0x" + Keys.getAddress(keyPair.getPublicKey());
        //私钥
        String privateKey = keyPair.getPrivateKey().toString(16);
        blockAddress.setPrivateKey(privateKey);
        //公钥
        String publicKey = keyPair.getPublicKey().toString(16);
        blockAddress.setPublicKey(publicKey);
        blockAddress.setAddress(address);
        if (privateKey.length() < 64) {
            throw new ServiceException("私钥异常");
        }
        return blockAddress;
    }
  
  
  
  
//导入jar包  
          <dependency>
            <groupId>org.bitcoinj</groupId>
            <artifactId>bitcoinj-core</artifactId>
            <version>0.14.7</version>
        </dependency>
  
  
  
  
