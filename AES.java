package com.bylh.yyb.follow.utils;

import com.bylh.yyb.follow.enmu.ENUM_KEYSIZE;

import java.io.UnsupportedEncodingException;

/**
 * Created by Administrator on 2017/2/14.
 *
 * 使用：new AES().AESDecrypt(...)  new AES().AESEncrypt(...)
 */

public class AES {
    //! #代表以字为单位的块长
    /*!
    @Brief 代表以字为单位的块长
    */
    public int Nb; //
    //! #代表以字为单位的密钥长度
    /*!
    @Brief 代表以字为单位的密钥长度
    */
    public int Nk;//
    //! #轮数 ,轮数是10、12或14中的任意一个并且是基于密码分析学理论的
    /*!
    @Brief 轮数 ,轮数是10、12或14中的任意一个并且是基于密码分析学理论的
    @attention 它直接取决于密钥长度
    */
    public int Nr;//轮数 ,轮数是10、12或14中的任意一个并且是基于密码分析学理论的。
    //
    //! #the seed key
    /*!
    @Brief   size will be 4 * keySize from ctor
    */
    byte key[];
    byte w[][];
    byte State[][];
    String defaultKey = "1qff@WSX3edc$RFV5tgb^YHN7ujm*IK>9ol.(P:??[{++";

    byte Sbox[][] = {  // populate the Sbox matrix
    /* 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
    /*0*/  {0x63, 0x7c, 0x77, 0x7b, (byte) 0xf2, 0x6b, 0x6f, (byte) 0xc5, 0x30, 0x01, 0x67, 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, 0x76},
    /*1*/  {(byte) 0xca, (byte) 0x82, (byte) 0xc9, 0x7d, (byte) 0xfa, 0x59, 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, 0x72, (byte) 0xc0},
    /*2*/  {(byte) 0xb7, (byte) 0xfd, (byte) 0x93, 0x26, 0x36, 0x3f, (byte) 0xf7, (byte) 0xcc, 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, 0x71, (byte) 0xd8, 0x31, 0x15},
    /*3*/  {0x04, (byte) 0xc7, 0x23, (byte) 0xc3, 0x18, (byte) 0x96, 0x05, (byte) 0x9a, 0x07, 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, 0x27, (byte) 0xb2, 0x75},
    /*4*/  {0x09, (byte) 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, (byte) 0xa0, 0x52, 0x3b, (byte) 0xd6, (byte) 0xb3, 0x29, (byte) 0xe3, 0x2f, (byte) 0x84},
    /*5*/  {0x53, (byte) 0xd1, 0x00, (byte) 0xed, 0x20, (byte) 0xfc, (byte) 0xb1, 0x5b, 0x6a, (byte) 0xcb, (byte) 0xbe, 0x39, 0x4a, 0x4c, 0x58, (byte) 0xcf},
    /*6*/  {(byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, 0x43, 0x4d, 0x33, (byte) 0x85, 0x45, (byte) 0xf9, 0x02, 0x7f, 0x50, 0x3c, (byte) 0x9f, (byte) 0xa8},
    /*7*/  {0x51, (byte) 0xa3, 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, 0x38, (byte) 0xf5, (byte) 0xbc, (byte) 0xb6, (byte) 0xda, 0x21, 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2},
    /*8*/  {(byte) 0xcd, 0x0c, 0x13, (byte) 0xec, 0x5f, (byte) 0x97, 0x44, 0x17, (byte) 0xc4, (byte) 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    /*9*/  {0x60, (byte) 0x81, 0x4f, (byte) 0xdc, 0x22, 0x2a, (byte) 0x90, (byte) 0x88, 0x46, (byte) 0xee, (byte) 0xb8, 0x14, (byte) 0xde, 0x5e, 0x0b, (byte) 0xdb},
    /*a*/  {(byte) 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, (byte) 0xc2, (byte) 0xd3, (byte) 0xac, 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, 0x79},
    /*b*/  {(byte) 0xe7, (byte) 0xc8, 0x37, 0x6d, (byte) 0x8d, (byte) 0xd5, 0x4e, (byte) 0xa9, 0x6c, 0x56, (byte) 0xf4, (byte) 0xea, 0x65, 0x7a, (byte) 0xae, 0x08},
    /*c*/  {(byte) 0xba, 0x78, 0x25, 0x2e, 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd, 0x74, 0x1f, 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a},
    /*d*/  {0x70, 0x3e, (byte) 0xb5, 0x66, 0x48, 0x03, (byte) 0xf6, 0x0e, 0x61, 0x35, 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, 0x1d, (byte) 0x9e},
    /*e*/  {(byte) 0xe1, (byte) 0xf8, (byte) 0x98, 0x11, 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b, 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, 0x55, 0x28, (byte) 0xdf},
    /*f*/  {(byte) 0x8c, (byte) 0xa1, (byte) 0x89, 0x0d, (byte) 0xbf, (byte) 0xe6, 0x42, 0x68, 0x41, (byte) 0x99, 0x2d, 0x0f, (byte) 0xb0, 0x54, (byte) 0xbb, 0x16}
    };

    byte iSbox[][] = {  // populate the iSbox matrix
    /* 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
    /*0*/  {0x52, 0x09, 0x6a, (byte) 0xd5, 0x30, 0x36, (byte) 0xa5, 0x38, (byte) 0xbf, 0x40, (byte) 0xa3, (byte) 0x9e, (byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb},
    /*1*/  {0x7c, (byte) 0xe3, 0x39, (byte) 0x82, (byte) 0x9b, 0x2f, (byte) 0xff, (byte) 0x87, 0x34, (byte) 0x8e, 0x43, 0x44, (byte) 0xc4, (byte) 0xde, (byte) 0xe9, (byte) 0xcb},
    /*2*/  {0x54, 0x7b, (byte) 0x94, 0x32, (byte) 0xa6, (byte) 0xc2, 0x23, 0x3d, (byte) 0xee, 0x4c, (byte) 0x95, 0x0b, 0x42, (byte) 0xfa, (byte) 0xc3, 0x4e},
    /*3*/  {0x08, 0x2e, (byte) 0xa1, 0x66, 0x28, (byte) 0xd9, 0x24, (byte) 0xb2, 0x76, 0x5b, (byte) 0xa2, 0x49, 0x6d, (byte) 0x8b, (byte) 0xd1, 0x25},
    /*4*/  {0x72, (byte) 0xf8, (byte) 0xf6, 0x64, (byte) 0x86, 0x68, (byte) 0x98, 0x16, (byte) 0xd4, (byte) 0xa4, 0x5c, (byte) 0xcc, 0x5d, 0x65, (byte) 0xb6, (byte) 0x92},
    /*5*/  {0x6c, 0x70, 0x48, 0x50, (byte) 0xfd, (byte) 0xed, (byte) 0xb9, (byte) 0xda, 0x5e, 0x15, 0x46, 0x57, (byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84},
    /*6*/  {(byte) 0x90, (byte) 0xd8, (byte) 0xab, 0x00, (byte) 0x8c, (byte) 0xbc, (byte) 0xd3, 0x0a, (byte) 0xf7, (byte) 0xe4, 0x58, 0x05, (byte) 0xb8, (byte) 0xb3, 0x45, 0x06},
    /*7*/  {(byte) 0xd0, 0x2c, 0x1e, (byte) 0x8f, (byte) 0xca, 0x3f, 0x0f, 0x02, (byte) 0xc1, (byte) 0xaf, (byte) 0xbd, 0x03, 0x01, 0x13, (byte) 0x8a, 0x6b},
    /*8*/  {0x3a, (byte) 0x91, 0x11, 0x41, 0x4f, 0x67, (byte) 0xdc, (byte) 0xea, (byte) 0x97, (byte) 0xf2, (byte) 0xcf, (byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6, 0x73},
    /*9*/  {(byte) 0x96, (byte) 0xac, 0x74, 0x22, (byte) 0xe7, (byte) 0xad, 0x35, (byte) 0x85, (byte) 0xe2, (byte) 0xf9, 0x37, (byte) 0xe8, 0x1c, 0x75, (byte) 0xdf, 0x6e},
    /*a*/  {0x47, (byte) 0xf1, 0x1a, 0x71, 0x1d, 0x29, (byte) 0xc5, (byte) 0x89, 0x6f, (byte) 0xb7, 0x62, 0x0e, (byte) 0xaa, 0x18, (byte) 0xbe, 0x1b},
    /*b*/  {(byte) 0xfc, 0x56, 0x3e, 0x4b, (byte) 0xc6, (byte) 0xd2, 0x79, 0x20, (byte) 0x9a, (byte) 0xdb, (byte) 0xc0, (byte) 0xfe, 0x78, (byte) 0xcd, 0x5a, (byte) 0xf4},
    /*c*/  {0x1f, (byte) 0xdd, (byte) 0xa8, 0x33, (byte) 0x88, 0x07, (byte) 0xc7, 0x31, (byte) 0xb1, 0x12, 0x10, 0x59, 0x27, (byte) 0x80, (byte) 0xec, 0x5f},
    /*d*/  {0x60, 0x51, 0x7f, (byte) 0xa9, 0x19, (byte) 0xb5, 0x4a, 0x0d, 0x2d, (byte) 0xe5, 0x7a, (byte) 0x9f, (byte) 0x93, (byte) 0xc9, (byte) 0x9c, (byte) 0xef},
    /*e*/  {(byte) 0xa0, (byte) 0xe0, 0x3b, 0x4d, (byte) 0xae, 0x2a, (byte) 0xf5, (byte) 0xb0, (byte) 0xc8, (byte) 0xeb, (byte) 0xbb, 0x3c, (byte) 0x83, 0x53, (byte) 0x99, 0x61},
    /*f*/  {0x17, 0x2b, 0x04, 0x7e, (byte) 0xba, 0x77, (byte) 0xd6, 0x26, (byte) 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d} };

    byte Rcon[][] = { {0x00, 0x00, 0x00, 0x00}, //轮常数表
        {0x01, 0x00, 0x00, 0x00},
        {0x02, 0x00, 0x00, 0x00},
        {0x04, 0x00, 0x00, 0x00},
        {0x08, 0x00, 0x00, 0x00},
        {0x10, 0x00, 0x00, 0x00},
        {0x20, 0x00, 0x00, 0x00},
        {0x40, 0x00, 0x00, 0x00},
        {(byte) 0x80, 0x00, 0x00, 0x00},
        {0x1b, 0x00, 0x00, 0x00},
        {0x36, 0x00, 0x00, 0x00} };

    public byte[] RotWord( byte word[] ) {//左旋一位
        byte result[] = new byte[4];
        result[0] = word[1];
        result[1] = word[2];
        result[2] = word[3];
        result[3] = word[0];
        return result;
    };

    public byte[] SubWord( byte word[] ) {//用替换表 Sbox 对一给定的一行密钥调度表 w[] 进行逐字节替换。
        byte result[] = new byte[4];
        result[0] = Sbox[ (word[0]&0xff) >> 4][ word[0] & 0x0f ];
        result[1] = Sbox[ (word[1]&0xff) >> 4][ word[1] & 0x0f ];
        result[2] = Sbox[ (word[2]&0xff) >> 4][ word[2] & 0x0f ];
        result[3] = Sbox[ (word[3]&0xff) >> 4][ word[3] & 0x0f ];
        return result;
    }

    public AES() {
        ENUM_KEYSIZE keysize = ENUM_KEYSIZE.BIT128;
        byte[] key = new byte[0];
        try {
            key = defaultKey.getBytes("GBK");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        InitAES(keysize,key);
    }

    /**
     * 使用默认的Key
     * @param keySize
     */
    public AES(ENUM_KEYSIZE keySize) {
        byte[] key = new byte[0];
        try {
            key = defaultKey.getBytes("GBK");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        InitAES(keySize,key);
    }

    /**
     * 自定义Key为byte[]数组
     * @param keySize
     * @param inKey
     */
    public AES(ENUM_KEYSIZE keySize, byte inKey[] ) {
        InitAES(keySize,inKey);
    }

    /**
     * 自定义Key为字符串
     * @param keysize
     * @param inKey
     */
    public AES(ENUM_KEYSIZE keysize, String inKey) {
        //直接写入密码
        byte[] key = new byte[16];
        try {
            byte temp[] = inKey.getBytes("GBK");
            if(temp.length < 16){
                System.arraycopy(temp,0,key,0,temp.length);
            }else{
                key = temp;
            }
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        InitAES(keysize,key);
    }

    public void InitAES(ENUM_KEYSIZE keysize, byte key[] ) {
        Nb = 4;
        switch( keysize) {
            case BIT128:
                Nk = 4;
                Nr = 10;
                break;
            case BIT192:
                Nk = 6;
                Nr = 12;
                break;
            case BIT256:
            default:
                Nk = 8;
                Nr = 14;
                break;
        }
        this.key = new byte[Nk * 4];
        System.arraycopy(key,0,this.key,0,Nk*4);
        w = new byte[Nb * (Nr+1)][4];   //w[]为密钥调度表
        //w[] 最初的 Nk (6) 行被作为种子，用原始密钥值
        int row;
        for(row = 0; row < Nk; ++row ) {
            w[row][0] = this.key[4*row];
            w[row][1] = this.key[4*row+1];
            w[row][2] = this.key[4*row+2];
            w[row][3] = this.key[4*row+3];
        }
        byte temp[] = new byte[4];
        for(  row = Nk; row < Nb *(Nr + 1); ++ row )
        {
            temp[0] = w[row-1][0];
            temp[1] = w[row-1][1];
            temp[2] = w[row-1][2];
            temp[3] = w[row-1][3];
            if (row % Nk == 0) {
                temp = SubWord(RotWord(temp));//this change two size
                temp[0] = (byte)( (int)temp[0] ^ (int)Rcon[row/Nk][0] );
                temp[1] = (byte)( (int)temp[1] ^ (int)Rcon[row/Nk][1] );
                temp[2] = (byte)( (int)temp[2] ^ (int)Rcon[row/Nk][2] );
                temp[3] = (byte)( (int)temp[3] ^ (int)Rcon[row/Nk][3] );
            }
            else if ( Nk > 6 && (row % Nk == 4) ) {
                temp = SubWord(temp);
            }
            // w[row] = w[row-Nk] xor temp
            w[row][0] = (byte) ( (int)w[row-Nk][0] ^ (int)temp[0] );
            w[row][1] = (byte) ( (int)w[row-Nk][1] ^ (int)temp[1] );
            w[row][2] = (byte) ( (int)w[row-Nk][2] ^ (int)temp[2] );
            w[row][3] = (byte) ( (int)w[row-Nk][3] ^ (int)temp[3] );
        }//loop
        if(State == null){
            State = new byte[4][Nb];
        }
    }

    public void Cipher( byte input[], byte output[] ) {
        int i;
        for (i = 0; i < (4 * Nb); ++i)
        {
            State[i%4][i/4] = input[i];
        }
        AddRoundKey(0);
        for (int round = 1; round <= (Nr - 1); ++round)  // main round loop
        {
            Subbytes();
            ShiftRows();
            MixColumns();
            AddRoundKey(round);
        }  // main round loop
        Subbytes();
        ShiftRows();
        AddRoundKey(Nr);

        // output = state
        for ( i = 0; i < (4 * Nb); ++i)
        {
            output[i] = State[i % 4][ i / 4];
        }
    }

    public void InvCipher( byte input[], byte output[] ) {
        int i;
        if (State[0] == null) {
            for(i=0;i<4;i++)
            {
                State[i] = new byte[Nb];
            }
        }

        for (i = 0; i < (4 * Nb); ++i) {
            State[i % 4][ i / 4] = input[i];
        }

        AddRoundKey(Nr);

        for (int round = Nr-1; round >= 1; --round)  // main round loop
        {
            InvShiftRows();
            InvSubbytes();
            AddRoundKey(round);
            InvMixColumns();
        }  // end main round loop for InvCipher

        InvShiftRows();
        InvSubbytes();
        AddRoundKey(0);

        // output = state
        for ( i = 0; i < (4 * Nb); ++i)
        {
            output[i] = State[i % 4][ i / 4];
        }
    }

    public void AddRoundKey( int round ) {
        for (int r = 0; r < 4; ++r)
        {
            for (int c = 0; c < 4; ++c)
            {
                State[r][c] = (byte) ( (int)State[r][c] ^ (int)w[(round*4)+c][r] );
            }
        }
    }

    public void Subbytes() {
        for (int r = 0; r < 4; ++r)
        {
            for (int c = 0; c < 4; ++c)
            {
                State[r][c] = Sbox[ ((State[r][c]&0xff) >> 4)][ (State[r][c] & 0x0f) ];
            }
        }
    }

    public void InvSubbytes() {
        for (int r = 0; r < 4; ++r)
        {
            for (int c = 0; c < 4; ++c)
            {
                State[r][c] = iSbox[ ((State[r][c]&0xff) >> 4)][ (State[r][c] & 0x0f) ];
            }
        }
    }

    public void ShiftRows() {
        byte temp[][] = new byte[4][4];
        //  byte[,] temp = new byte[4,4];
        int r;
        for (r = 0; r < 4; ++r)  // copy State into temp[]
        {
            for (int c = 0; c < 4; ++c)
            {
                temp[r][c] = State[r][c];
                // temp[r,c] = this.State[r,c];
            }
        }

        for ( r = 1; r < 4; ++r)  // shift temp into State
        {
            for (int c = 0; c < 4; ++c)
            {
                State[r][c] = temp[ r][ (c + r) % Nb ];
            }
        }
    }  // ShiftRows()


    public void InvShiftRows() {
        int r;
        byte temp[][] = new byte[4][4];
        for (r = 0; r < 4; ++r)  // copy State into temp[]
        {
            for (int c = 0; c < 4; ++c)
            {
                temp[r][c] = State[r][c];
            }
        }
        for ( r = 1; r < 4; ++r)  // shift temp into State
        {
            for (int c = 0; c < 4; ++c)
            {
                State[r][ (c + r) % Nb ] = temp[r][c];
            }
        }
    }  // InvShiftRows()

    public void MixColumns() {
        byte temp[][] = new byte[4][4];
        for (int r = 0; r < 4; ++r)  // copy State into temp[]
        {
            for (int c = 0; c < 4; ++c)
            {
                temp[r][c] = State[r][c];
            }
        }

        for (int c = 0; c < 4; ++c)
        {
            State[0][c] = (byte) ( (int)gfmultby02(temp[0][c]) ^ (int)gfmultby03(temp[1][c]) ^
                (int)gfmultby01(temp[2][c]) ^ (int)gfmultby01(temp[3][c]) );

            State[1][c] = (byte) ( (int)gfmultby01(temp[0][c]) ^ (int)gfmultby02(temp[1][c]) ^
                (int)gfmultby03(temp[2][c]) ^ (int)gfmultby01(temp[3][c]) );
            State[2][c] = (byte) ( (int)gfmultby01(temp[0][c]) ^ (int)gfmultby01(temp[1][c]) ^
                (int)gfmultby02(temp[2][c]) ^ (int)gfmultby03(temp[3][c]) );
            State[3][c] = (byte) ( (int)gfmultby03(temp[0][c]) ^ (int)gfmultby01(temp[1][c]) ^
                (int)gfmultby01(temp[2][c]) ^ (int)gfmultby02(temp[3][c]) );
        }
    }  // MixColumns

    public void InvMixColumns() {
        byte temp[][] = new byte[4][4];
        for (int r = 0; r < 4; ++r)  // copy State into temp[]
        {
            for (int c = 0; c < 4; ++c) {
                temp[r][c] = State[r][c];
            }
        }
        for (int c = 0; c < 4; ++c) {
            State[0][c] = (byte) ( (int)gfmultby0e(temp[0][c]) ^ (int)gfmultby0b(temp[1][c]) ^
                (int)gfmultby0d(temp[2][c]) ^ (int)gfmultby09(temp[3][c]) );
            State[1][c] = (byte) ( (int)gfmultby09(temp[0][c]) ^ (int)gfmultby0e(temp[1][c]) ^
                (int)gfmultby0b(temp[2][c]) ^ (int)gfmultby0d(temp[3][c]) );
            State[2][c] = (byte) ( (int)gfmultby0d(temp[0][c]) ^ (int)gfmultby09(temp[1][c]) ^
                (int)gfmultby0e(temp[2][c]) ^ (int)gfmultby0b(temp[3][c]) );
            State[3][c] = (byte) ( (int)gfmultby0b(temp[0][c]) ^ (int)gfmultby0d(temp[1][c]) ^
                (int)gfmultby09(temp[2][c]) ^ (int)gfmultby0e(temp[3][c]) );
        }
    }

    /**
     * 加密内容为byte[]数组
     * @param input
     * @return
     */
    public byte[] AESEncrypt(byte input[]) {
        int nbyte = input.length;
        boolean bTail = false;
        int nOneSize = 4 * Nb;//16
        int nCount = nbyte / nOneSize;
        if (nbyte % nOneSize != 0) {
            bTail = true;
            ++nCount;
        }
        byte[] output = new byte [nOneSize * nCount];
        byte pInTemp[] = new byte[nOneSize];
        byte pOutTemp[] = new byte[nOneSize];
        for (int i = 0; i < nCount; ++i) {
            for(int k = 0;k < nOneSize;k++){
                pOutTemp[k] = 0;
            }
            if ((i == nCount - 1) && (bTail == true)) {
                for(int k = 0;k < nOneSize;k++){
                    pInTemp[k] = 0;
                }
                System.arraycopy(input,nOneSize*i,pInTemp,0,nbyte % nOneSize);
            }
            else {
                System.arraycopy(input,nOneSize*i,pInTemp,0,nOneSize);
            }
            Cipher(pInTemp, pOutTemp);
            System.arraycopy(pOutTemp,0,output,nOneSize*i,nOneSize);
        }
        return output;
    }

    /**
     * 加密内容为字符串
     * @param pwd
     * @return
     */
    public byte[] AESEncrypt(String pwd) {
        byte[] input = new byte[0];
        try {
            input = pwd.getBytes("GBK");
            int nbyte = input.length;
            boolean bTail = false;
            int nOneSize = 4 * Nb;//16
            int nCount = nbyte / nOneSize;
            if (nbyte % nOneSize != 0) {
                bTail = true;
                ++nCount;
            }
            byte[] output = new byte [nOneSize * nCount];
            byte pInTemp[] = new byte[nOneSize];
            byte pOutTemp[] = new byte[nOneSize];
            for (int i = 0; i < nCount; ++i) {
                for(int k = 0;k < nOneSize;k++){
                    pOutTemp[k] = 0;
                }
                if ((i == nCount - 1) && (bTail == true)) {
                    for(int k = 0;k < nOneSize;k++){
                        pInTemp[k] = 0;
                    }
                    System.arraycopy(input,nOneSize*i,pInTemp,0,nbyte % nOneSize);
                }
                else {
                    System.arraycopy(input,nOneSize*i,pInTemp,0,nOneSize);
                }
                Cipher(pInTemp, pOutTemp);
                System.arraycopy(pOutTemp,0,output,nOneSize*i,nOneSize);
            }
            return output;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }

    /**
     * 解密
     * @param input
     * @return
     */
    public String AESDecrypt(byte input[]) {
        int nbyte = input.length;
        boolean bTail = false;
        int nOneSize = 4 * Nb;
        int nCount = nbyte / nOneSize;
        if (nbyte % nOneSize != 0) {
            bTail = true;
            ++nCount;
        }
        byte output[] = new byte [nOneSize * nCount];
        byte pInTemp[] = new byte[nOneSize];
        byte pOutTemp[] = new byte[nOneSize];
        for (int i = 0; i < nCount; ++i) {
            for(int k = 0;k < nOneSize;k++){
                pOutTemp[k] = 0;
            }
            if ((i == nCount - 1) && (bTail == true)) {
                for(int k = 0;k < nOneSize;k++){
                    pInTemp[k] = 0;
                }
                System.arraycopy(input,nOneSize*i,pInTemp,0,nbyte % nOneSize);
            }
            else {
                System.arraycopy(input,nOneSize*i,pInTemp,0,nOneSize);
            }
            InvCipher(pInTemp, pOutTemp);
            System.arraycopy(pOutTemp,0,output,nOneSize*i,nOneSize);
        }
        String Out = ClientBaseUtils.Help_ReadString(output,0,output.length);
        return Out;
    }

    static byte gfmultby01(byte b)  //乘1
    {
        return b;
    }

//    static byte gfmultby02(byte b) //乘2
//    {
//        if (b < (byte)0x80){
//            return (byte)(int)(b << 1);
//        }
//        else{
//            return (byte)((int)(b  << 1) ^ (int)(0x1b) );
//        }
//    }

    static byte gfmultby02(byte b)//乘2
    {
        if (b >= 0 && b <= (byte)0x7F){
            return (byte)(int)(b << 1);
        }
        else
            return (byte)((int)(b  << 1) ^ (int)(0x1b));
    }

    static byte gfmultby03(byte b)
    {
        return (byte) ( (int)gfmultby02(b) ^ (int)b );//GF域的加法运算就是异或
    }

    static byte gfmultby09(byte b)
    {
        return (byte)( (int)gfmultby02(gfmultby02(gfmultby02(b))) ^
                (int)b );
    }

    static byte gfmultby0b(byte b)
    {
        return (byte)( (int)gfmultby02(gfmultby02(gfmultby02(b))) ^
                (int)gfmultby02(b) ^
                (int)b );
    }

    static byte gfmultby0d(byte b)
    {
        return (byte)( (int)gfmultby02(gfmultby02(gfmultby02(b))) ^
                (int)gfmultby02(gfmultby02(b)) ^
                (int)(b) );
    }

    static byte gfmultby0e(byte b)
    {
        return (byte)( (int)gfmultby02(gfmultby02(gfmultby02(b))) ^
                (int)gfmultby02(gfmultby02(b)) ^
                (int)gfmultby02(b) );
    }

}
