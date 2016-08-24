package sviolet.smcrypto.sm3;

public class SM3Digest {
    //SM3值的长度
    private static final int BYTE_LENGTH = 32;
    //SM3分组长度
    private static final int BLOCK_LENGTH = 64;
    //缓冲区长度
    private static final int BUFFER_LENGTH = BLOCK_LENGTH;

    //缓冲区
    private byte[] buff = new byte[BUFFER_LENGTH];
    //缓冲区偏移量
    private int buffOffset = 0;
    //块计数
    private int blockCounter = 0;
    //摘要值(暂存)
    private byte[] digestValue = SM3Algorithm.DEFAULT_IV.clone();

    public SM3Digest() {
    }

    public SM3Digest(SM3Digest digest) {
        System.arraycopy(digest.buff, 0, this.buff, 0, digest.buff.length);
        this.buffOffset = digest.buffOffset;
        this.blockCounter = digest.blockCounter;
        System.arraycopy(digest.digestValue, 0, this.digestValue, 0, digest.digestValue.length);
    }

    /**
     * 重置
     */
    public void reset() {
        buff = new byte[BUFFER_LENGTH];
        buffOffset = 0;
        blockCounter = 0;
        digestValue = SM3Algorithm.DEFAULT_IV.clone();
    }

    public void update(byte input) {
        update(new byte[]{input}, 0, 1);
    }

    /**
     * 输入
     *
     * @param input 输入数据
     */
    public void update(byte[] input) {
        update(input, 0, input.length);
    }

    /**
     * 输入
     *
     * @param input       输入数据
     * @param inputOffset 输入偏移量
     * @param len         输入长度
     */
    public void update(byte[] input, int inputOffset, int len) {
        if (input == null) {
            return;
        }
        int partLen = BUFFER_LENGTH - buffOffset;//buff剩余长度
        int inputLen = len;//输入长度
        int dPos = inputOffset;//运算偏移量

        //输入数据大于缓冲时, 进行摘要运算
        if (partLen < inputLen) {
            //填满缓冲
            System.arraycopy(input, dPos, buff, buffOffset, partLen);
            inputLen -= partLen;
            dPos += partLen;
            //将缓冲的数据进行摘要计算
            doUpdate();
            //继续, 直到缓冲能存下剩余数据
            while (inputLen > BUFFER_LENGTH) {
                System.arraycopy(input, dPos, buff, 0, BUFFER_LENGTH);
                inputLen -= BUFFER_LENGTH;
                dPos += BUFFER_LENGTH;
                doUpdate();
            }
        }

        //将剩余数据存入缓冲
        System.arraycopy(input, dPos, buff, buffOffset, inputLen);
        buffOffset += inputLen;
    }

    private void doUpdate() {
        //将缓冲区数据按块为单位划分, 进行摘要计算
        byte[] bytes = new byte[BLOCK_LENGTH];
        for (int i = 0; i < BUFFER_LENGTH; i += BLOCK_LENGTH) {
            System.arraycopy(buff, i, bytes, 0, bytes.length);
            doHash(bytes);
        }
        buffOffset = 0;
    }

    private void doHash(byte[] bytes) {
        //将暂存的摘要值与新数据送入, 进行摘要计算
        byte[] tmp = SM3Algorithm.digestBlock(digestValue, bytes);
        //记录摘要值
        System.arraycopy(tmp, 0, digestValue, 0, digestValue.length);
        blockCounter++;
    }

    public void doFinal(byte[] output, int offset) {
        try {
            //获取缓冲的剩余数据
            byte[] bytes = new byte[BLOCK_LENGTH];
            byte[] buffer = new byte[buffOffset];
            System.arraycopy(buff, 0, buffer, 0, buffer.length);
            //填充
            byte[] tmp = SM3Algorithm.paddingBlock(buffer, blockCounter);
            //划分为块做摘要计算
            for (int i = 0; i < tmp.length; i += BLOCK_LENGTH) {
                System.arraycopy(tmp, i, bytes, 0, bytes.length);
                doHash(bytes);
            }
            System.arraycopy(digestValue, 0, output, offset, BYTE_LENGTH);
        } finally {
            reset();
        }
    }

    /**
     * SM3结果输出
     */
    public byte[] doFinal() {
        byte[] result = new byte[BYTE_LENGTH];
        doFinal(result, 0);
        return result;
    }

}
