import java.util.*;

public class MD5 {

  private static final int INITIAL_A = 0x67452301;
  private static final int INITIAL_B = (int) 0xEFCDAB89L;
  private static final int INITIAL_C = (int) 0x98BADCFEL;
  private static final int INITIAL_D = 0x10325476;
  private static final int[] SHIFT_AMOUNTS = {
    7,
    12,
    17,
    22,
    5,
    9,
    14,
    20,
    4,
    11,
    16,
    23,
    6,
    10,
    15,
    21,
  };
  private static final int[] TABLE_T = new int[64];

  static {
    for (int i = 0; i < 64; i++) TABLE_T[i] =
      (int) (long) ((1L << 32) * Math.abs(Math.sin(i + 1)));
  }

  public static byte[] computeMD5(byte[] message) {
    int messageLengthBytes = message.length;
    int numBlocks = ((messageLengthBytes + 8) >>> 6) + 1;
    int totalLength = numBlocks << 6;
    byte[] paddingBytes = new byte[totalLength - messageLengthBytes];
    paddingBytes[0] = (byte) 0x80;
    long messageLengthBits = (long) messageLengthBytes << 3;

    for (int i = 0; i < 8; i++) {
      paddingBytes[paddingBytes.length - 8 + i] = (byte) messageLengthBits;
      messageLengthBits >>>= 8;
    }

    int a = INITIAL_A;
    int b = INITIAL_B;
    int c = INITIAL_C;
    int d = INITIAL_D;

    int[] buffer = new int[16];
    for (int i = 0; i < numBlocks; i++) {
      int index = i << 6;
      for (int j = 0; j < 64; j++, index++) {
        buffer[j >>> 2] =
          (
            (int) (
              (index < messageLengthBytes)
                ? message[index]
                : paddingBytes[index - messageLengthBytes]
            ) << 24
          ) |
          (buffer[j >>> 2] >>> 8);
      }

      int originalA = a;
      int originalB = b;
      int originalC = c;
      int originalD = d;
      for (int j = 0; j < 64; j++) {
        int div16 = j >>> 4;
        int f = 0;
        int bufferIndex = j;

        switch (div16) {
          case 0:
            f = (b & c) | (~b & d);
            break;
          case 1:
            f = (b & d) | (c & ~d);
            bufferIndex = (bufferIndex * 5 + 1) & 0x0F;
            break;
          case 2:
            f = b ^ c ^ d;
            bufferIndex = (bufferIndex * 3 + 5) & 0x0F;
            break;
          case 3:
            f = c ^ (b | ~d);
            bufferIndex = (bufferIndex * 7) & 0x0F;
            break;
        }

        int temp =
          b +
          Integer.rotateLeft(
            a + f + buffer[bufferIndex] + TABLE_T[j],
            SHIFT_AMOUNTS[(div16 << 2) | (j & 3)]
          );

        a = d;
        d = c;
        c = b;
        b = temp;
      }

      a += originalA;
      b += originalB;
      c += originalC;
      d += originalD;
    }

    byte[] md5 = new byte[16];
    int count = 0;
    for (int i = 0; i < 4; i++) {
      int n = (i == 0) ? a : ((i == 1) ? b : ((i == 2) ? c : d));
      for (int j = 0; j < 4; j++) {
        md5[count++] = (byte) n;
        n >>>= 8;
      }
    }
    return md5;
  }

  public static String toHexString(byte[] bytes) {
    StringBuilder stringBuilder = new StringBuilder();
    for (int i = 0; i < bytes.length; i++) {
      stringBuilder.append(String.format("%02X", bytes[i] & 0xFF));
    }
    return stringBuilder.toString();
  }

  public static void main(String[] args) {
    String[] stringArr = {
      "They are deterministic",
      "21BDS0387",
      "Sai Sreekar",
      "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
    };

    for (String testString : stringArr) {
      System.out.println(
        "0x" +
        toHexString(computeMD5(testString.getBytes())) +
        " <== \"" +
        testString +
        "\""
      );
    }
    return;
  }
}
