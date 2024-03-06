#include <iostream>
#include <vector>
using namespace std;

string hexToBin(string hexString)
{
    string binaryRes = "";
    for (int i = 0; i < hexString.size(); i++)
    {
        switch (hexString[i])
        {
        case '0':
            binaryRes += "0000";
            break;
        case '1':
            binaryRes += "0001";
            break;
        case '2':
            binaryRes += "0010";
            break;
        case '3':
            binaryRes += "0011";
            break;
        case '4':
            binaryRes += "0100";
            break;
        case '5':
            binaryRes += "0101";
            break;
        case '6':
            binaryRes += "0110";
            break;
        case '7':
            binaryRes += "0111";
            break;
        case '8':
            binaryRes += "1000";
            break;
        case '9':
            binaryRes += "1001";
            break;
        case 'A':
        case 'a':
            binaryRes += "1010";
            break;
        case 'B':
        case 'b':
            binaryRes += "1011";
            break;
        case 'C':
        case 'c':
            binaryRes += "1100";
            break;
        case 'D':
        case 'd':
            binaryRes += "1101";
            break;
        case 'E':
        case 'e':
            binaryRes += "1110";
            break;
        case 'F':
        case 'f':
            binaryRes += "1111";
            break;
        default:
            cout << "Error: Invalid hexadecimal digit" << endl;
            return "";
        }
    }
    return binaryRes;
}

string binToHex(string binaryStr)
{
    string hexRes = "";
    for (int i = 0; i < binaryStr.size(); i += 4)
    {
        string bin = binaryStr.substr(i, 4);
        if (bin == "0000")
        {
            hexRes += "0";
        }
        else if (bin == "0001")
        {
            hexRes += "1";
        }
        else if (bin == "0010")
        {
            hexRes += "2";
        }
        else if (bin == "0011")
        {
            hexRes += "3";
        }
        else if (bin == "0100")
        {
            hexRes += "4";
        }
        else if (bin == "0101")
        {
            hexRes += "5";
        }
        else if (bin == "0110")
        {
            hexRes += "6";
        }
        else if (bin == "0111")
        {
            hexRes += "7";
        }
        else if (bin == "1000")
        {
            hexRes += "8";
        }
        else if (bin == "1001")
        {
            hexRes += "9";
        }
        else if (bin == "1010")
        {
            hexRes += "A";
        }
        else if (bin == "1011")
        {
            hexRes += "B";
        }
        else if (bin == "1100")
        {
            hexRes += "C";
        }
        else if (bin == "1101")
        {
            hexRes += "D";
        }
        else if (bin == "1110")
        {
            hexRes += "E";
        }
        else if (bin == "1111")
        {
            hexRes += "F";
        }
        else
        {
            cout << "Error: Invalid binary digit" << endl;
            return "";
        }
    }

    return hexRes;
}

string decToBin(int dec)
{
    string bin = "";
    while (dec > 0)
    {
        if (dec % 2 == 0)
        {
            bin = "0" + bin;
        }
        else
        {
            bin = "1" + bin;
        }
        dec /= 2;
    }
    return bin;
}

string binToDec(string bin)
{
    int dec = 0;
    int base = 1;
    for (int i = bin.size() - 1; i >= 0; i--)
    {
        if (bin[i] == '1')
        {
            dec += base;
        }
        base *= 2;
    }
    return to_string(dec);
}

class DESEncryption
{
private:
    const int pc1Table[56] = {57, 49, 41, 33, 25, 17, 9,
                              1, 58, 50, 42, 34, 26, 18,
                              10, 2, 59, 51, 43, 35, 27,
                              19, 11, 3, 60, 52, 44, 36,
                              63, 55, 47, 39, 31, 23, 15,
                              7, 62, 54, 46, 38, 30, 22,
                              14, 6, 61, 53, 45, 37, 29,
                              21, 13, 5, 28, 20, 12, 4};

    const int pc2Table[48] = {14, 17, 11, 24, 1, 5,
                              3, 28, 15, 6, 21, 10,
                              23, 19, 12, 4, 26, 8,
                              16, 7, 27, 20, 13, 2,
                              41, 52, 31, 37, 47, 55,
                              30, 40, 51, 45, 33, 48,
                              44, 49, 39, 56, 34, 53,
                              46, 42, 50, 36, 29, 32};

    const int ipTable[64] = {58, 50, 42, 34, 26, 18, 10, 2,
                             60, 52, 44, 36, 28, 20, 12, 4,
                             62, 54, 46, 38, 30, 22, 14, 6,
                             64, 56, 48, 40, 32, 24, 16, 8,
                             57, 49, 41, 33, 25, 17, 9, 1,
                             59, 51, 43, 35, 27, 19, 11, 3,
                             61, 53, 45, 37, 29, 21, 13, 5,
                             63, 55, 47, 39, 31, 23, 15, 7};

    const int expansionTable[48] = {32, 1, 2, 3, 4, 5,
                                    4, 5, 6, 7, 8, 9,
                                    8, 9, 10, 11, 12, 13,
                                    12, 13, 14, 15, 16, 17,
                                    16, 17, 18, 19, 20, 21,
                                    20, 21, 22, 23, 24, 25,
                                    24, 25, 26, 27, 28, 29,
                                    28, 29, 30, 31, 32, 1};

    const int sBoxes[8][4][16] = {
        {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
         {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
         {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
         {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
        {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
         {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
         {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
         {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
        {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
         {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
         {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
         {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
        {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
         {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
         {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
         {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
        {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
         {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
         {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
         {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
        {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
         {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
         {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
         {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
        {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
         {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
         {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
         {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
        {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
         {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
         {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
         {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}};

    const int pBox[32] = {16, 7, 20, 21,
                          29, 12, 28, 17,
                          1, 15, 23, 26,
                          5, 18, 31, 10,
                          2, 8, 24, 14,
                          32, 27, 3, 9,
                          19, 13, 30, 6,
                          22, 11, 4, 25};

    const int inverseIpTable[64] = {40, 8, 48, 16, 56, 24, 64, 32,
                                    39, 7, 47, 15, 55, 23, 63, 31,
                                    38, 6, 46, 14, 54, 22, 62, 30,
                                    37, 5, 45, 13, 53, 21, 61, 29,
                                    36, 4, 44, 12, 52, 20, 60, 28,
                                    35, 3, 43, 11, 51, 19, 59, 27,
                                    34, 2, 42, 10, 50, 18, 58, 26,
                                    33, 1, 41, 9, 49, 17, 57, 25};

    const int shiftTable[16] = {1, 1, 2, 2,
                                2, 2, 2, 2,
                                1, 2, 2, 2,
                                2, 2, 2, 1};

    string shiftBits(string s, int n)
    {
        if (n < 0)
        {
            cout << "Error: Shift bits cannot be negative" << endl;
            return "";
        }

        if (n > s.length())
        {
            cout << "Error: Shift bits cannot be greater than the length of the string" << endl;
            return "";
        }

        string result = s.substr(n, s.length() - n) + s.substr(0, n);
        return result;
    }

    string expand32To48(string s32)
    {
        if (s32.size() != 32)
        {
            cout << "Error: Input string is not of size 32" << endl;
            return "";
        }

        string s48 = "";
        for (int i = 0; i < 48; i++)
        {
            s48 += s32[expansionTable[i] - 1];
        }
        return s48;
    }

    string getXOR(string a, string b)
    {
        if (a.size() != b.size())
        {
            cout << "Error: XOR operation is not possible on strings of different sizes" << endl;
            return "";
        }

        string result = "";
        for (int i = 0; i < a.length(); i++)
        {
            result += (a[i] == b[i]) ? "0" : "1";
        }
        return result;
    }

    string getSBoxResult(string s, int k)
    {
        if (s.size() != 6)
        {
            cout << "Error: Input string is not of size 6" << endl;
            return "";
        }
        if (k < 0 || k > 7)
        {
            cout << "Error: SBox index is out of range" << endl;
            return "";
        }

        int row = 2 * (s[0] - '0') + (s[5] - '0');
        int col = 8 * (s[1] - '0') + 4 * (s[2] - '0') + 2 * (s[3] - '0') + (s[4] - '0');
        int val = sBoxes[k][row][col];
        string result = "";

        // to binary
        while (val > 0)
        {
            if (val % 2 == 0)
            {
                result = "0" + result;
            }
            else
            {
                result = "1" + result;
            }
            val /= 2;
        }

        while (result.length() < 4)
        {
            result = "0" + result;
        }

        return result;
    }

    string getPBoxResult(string s32)
    {
        if (s32.size() != 32)
        {
            cout << "Error: Input string is not of size 32" << endl;
            return "";
        }

        string result = "";
        for (int i = 0; i < 32; i++)
        {
            result += s32[pBox[i] - 1];
        }
        return result;
    }

    string getPC1Result(string key64)
    {
        if (key64.size() != 64)
        {
            cout << "Error: Input string is not of size 64" << endl;
            return "";
        }

        string res56 = "";
        for (int i = 0; i < 56; i++)
        {
            res56 += key64[pc1Table[i] - 1];
        }
        return res56;
    }

    string getPC2Result(string key56)
    {
        if (key56.size() != 56)
        {
            cout << "Error: Input string is not of size 56" << endl;
            return "";
        }

        string res48 = "";
        for (int i = 0; i < 48; i++)
        {
            res48 += key56[pc2Table[i] - 1];
        }
        return res48;
    }

    string getIPResult(string plainText64)
    {
        if (plainText64.size() != 64)
        {
            cout << "Error: Input string is not of size 64" << endl;
            return "";
        }

        string res64 = "";
        for (int i = 0; i < 64; i++)
        {
            res64 += plainText64[ipTable[i] - 1];
        }
        return res64;
    }

    string getInverseIPResult(string plainText64)
    {
        if (plainText64.size() != 64)
        {
            cout << "Error: Input string is not of size 64" << endl;
            return "";
        }

        string res64 = "";
        for (int i = 0; i < 64; i++)
        {
            res64 += plainText64[inverseIpTable[i] - 1];
        }
        return res64;
    }

    string desFFunction(string rightHalfPt32, string roundKey48, int roundNum)
    {
        if (rightHalfPt32.size() != 32)
        {
            cout << "Error: Input string is not of size 32" << endl;
            return "";
        }

        string expandedRightHalfPt48 = expand32To48(rightHalfPt32);
        string xorResult = getXOR(expandedRightHalfPt48, roundKey48);
        string sBoxResult = "";
        for (int i = 0; i < 8; i++)
        {
            sBoxResult += getSBoxResult(xorResult.substr(i * 6, 6), i);
        }
        string pBoxResult = getPBoxResult(sBoxResult);
        return pBoxResult;
    }

    vector<string> keyGeneration(string key)
    {
        string key64 = hexToBin(key);
        string key56 = getPC1Result(key64);
        string leftHalfKey = key56.substr(0, 28);
        string rightHalfKey = key56.substr(28, 28);
        vector<string> roundKeys(16);

        for (int i = 0; i < 16; i++)
        {
            leftHalfKey = shiftBits(leftHalfKey, shiftTable[i]);
            rightHalfKey = shiftBits(rightHalfKey, shiftTable[i]);
            roundKeys[i] = getPC2Result(leftHalfKey + rightHalfKey);
        }

        // print round keys
        for (int i = 0; i < 16; i++)
        {
            cout << "Round " << i + 1 << " Key: " << binToHex(roundKeys[i]) << endl;
        }

        return roundKeys;
    }

public:
    string encrypt(const string plainText, const string key)
    {
        vector<string> roundKeys = keyGeneration(key);

        string plainText64 = hexToBin(plainText);
        string ipText = getIPResult(plainText64);
        string leftHalfPt = ipText.substr(0, 32);
        string rightHalfPt = ipText.substr(32, 32);
        for (int i = 0; i < 16; i++)
        {
            string temp = rightHalfPt;
            rightHalfPt = getXOR(leftHalfPt, desFFunction(rightHalfPt, roundKeys[i], i));
            leftHalfPt = temp;
        }
        string temp = leftHalfPt;
        leftHalfPt = rightHalfPt;
        rightHalfPt = temp;

        string cipherText = getInverseIPResult(leftHalfPt + rightHalfPt);
        return binToHex(cipherText);
    }

    string decrypt(const string cypherText, const string key)
    {
        vector<string> roundKeys = keyGeneration(key);

        string cypherText64 = hexToBin(cypherText);
        string ipText = getIPResult(cypherText64);
        string leftHalfCt = ipText.substr(0, 32);
        string rightHalfCt = ipText.substr(32, 32);
        for (int i = 0; i < 16; i++)
        {
            string temp = rightHalfCt;
            rightHalfCt = getXOR(leftHalfCt, desFFunction(rightHalfCt, roundKeys[15 - i], i));
            leftHalfCt = temp;
        }

        string temp = leftHalfCt;
        leftHalfCt = rightHalfCt;
        rightHalfCt = temp;

        string plainText64 = getInverseIPResult(leftHalfCt + rightHalfCt);

        return binToHex(plainText64);
    }
};

int main()
{
    DESEncryption des;
    string key = "133457799BBCDFF1";
    string plainText = "0123456789ABCDEF";

    cout << "Encrytpion: \n";
    string cypherTextRes = des.encrypt(plainText, key);
    cout << "Cipher Text: " << cypherTextRes << endl;

    cout << "\nDecryption: \n";
    string cypherText = "85E813540F0AB405";
    string plainTextRes = des.decrypt(cypherText, key);
    cout << "Plain Text: " << plainTextRes << endl;

    return 0;
}