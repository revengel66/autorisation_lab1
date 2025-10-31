package com.example.autorisation.security;


import java.util.Arrays;

public final class Sha256Hasher {
    private static final int BLOCK_SIZE = 64; // 512 bits  длина одного блока данных
    private static final int DIGEST_LENGTH = 32; // 256 bits длина итогового хеша


    //1 Этап. Константы. Инициализационные хеши и константы раундов.
    private static final int[] INITIAL_HASHES = computeInitialHashes();
    private static final int[] ROUND_CONSTANTS = computeRoundConstants();
    //дробную часть квадратных корней первых 8 простых и умножаем на 2^32, чтобы получить 32‑битные слова.
    private static int[] computeInitialHashes() {
        int[] primes = firstPrimes(8);
        int[] hashes = new int[8];
        for (int i = 0; i < primes.length; i++) {
            double sqrt = Math.sqrt(primes[i]);
            double fractional = sqrt - Math.floor(sqrt); //оставляет только дробную часть корня простого числа
            long word = (long) (fractional * (1L << 32)); //fractional * (1L << 32) умножает дробную часть на 2^32 и отбрасываем дробнукю часть с помощью long
            hashes[i] = (int) word;
        }

        return hashes;

    }

    //берем дробные части кубических корней первых 64 простых и умножаем на 2^32
    private static int[] computeRoundConstants() {
        int[] primes = firstPrimes(64);
        int[] constants = new int[64];

        for (int i = 0; i < primes.length; i++) {
            double cbrt = Math.cbrt(primes[i]);
            double fractional = cbrt - Math.floor(cbrt);
            long word = (long) (fractional * (1L << 32));
            constants[i] = (int) word;
        }

        return constants;

    }
    //вычисление первых n простых чисел
    private static int[] firstPrimes(int count) {

            int[] primes = new int[count];
            int found = 0;
            int candidate = 2;

            while (found < count) {
                boolean isPrime = true;

                for (int i = 0; i < found; i++) {
                    int prime = primes[i];
                    if ((long) prime * prime > candidate) {
                        break;
                    }
                    if (candidate % prime == 0) {
                        isPrime = false;
                        break;
                    }
                }

                if (isPrime) {
                    primes[found++] = candidate;
                }

                candidate++;
            }

            return primes;
        }



    //2 Этап. Подготовка сообщения: дополнение и разбиение на блоки.

    //    Padding — это шаг «доукомплектования» исходного сообщения до нужного формата, с которым SHA‑256 умеет работать. Алгоритм обрабатывает данные только кусками ровно по 64
    //    байта. Но любое сообщение редко имеет длину, кратную 64, и мы должны однозначно зафиксировать, где оно заканчивается. Поэтому padMessage делает три вещи:
    //
    //    1. Добавляет в конец сообщения специальный байт 10000000 (0x80). Это гарантированная отметка «вот тут сообщение закончилось».
    //    2. Затем вставляет нужное количество нулей, чтобы общий размер стал «64‑байтовые блоки минус последние 8 байтов». Обычно это несколько нулевых байтов.
    //    3. В последние 8 байтов записывает оригинальную длину сообщения в битах. По стандарту, это big-endian число.
    //
    //    Итого, после padMessage у нас получаются блоки длиной 64 байта, которые можно поштучно подавать в основную часть SHA‑256. Алгоритм будет знать, где «настоящие данные», а
    //    где добавка, потому что отметка и длина однозначно определяют конец исходного текста.
    private static byte[] padMessage(byte[] message) {
        long bitLength = (long) message.length * 8;

        int remainder = (message.length + 1 + 8) % BLOCK_SIZE;
        int paddingZeros = remainder == 0 ? 0 : BLOCK_SIZE - remainder;
        int totalLength = message.length + 1 + paddingZeros + 8;

        byte[] padded = new byte[totalLength];
        System.arraycopy(message, 0, padded, 0, message.length);

        padded[message.length] = (byte) 0x80;

        for (int i = 0; i < 8; i++) {
            padded[totalLength - 1 - i] = (byte) (bitLength >>> (8 * i));
        }

        return padded;
    }




    //3 Этап.  Расписание сообщений — массива W[0…63] для каждого 64-байтового блока

    //Первые 16 слов W — это сами байты блока, собранные по четыре в 32‑битное число (big-endian).
    //Нужно читать 4 байта как одно 32-битное число в big-endian.
    private static int readIntBigEndian(byte[] block, int offset) {
        return ((block[offset] & 0xFF) << 24)
                | ((block[offset + 1] & 0xFF) << 16)
                | ((block[offset + 2] & 0xFF) << 8)
                | (block[offset + 3] & 0xFF);
    }
    private static int[] prepareMessageSchedule(byte[] block) {
        int[] w = new int[64];
        for (int i = 0; i < 16; i++) {
            int offset = i * 4;
            w[i] = readIntBigEndian(block, offset);
        }
        //Расширяем расписание до 64 слов.
        for (int i = 16; i < 64; i++) {
            int s0 = sigma0(w[i - 15]);
            int s1 = sigma1(w[i - 2]);
            long sum = (w[i - 16] & 0xFFFFFFFFL)
                    + (s0 & 0xFFFFFFFFL)
                    + (w[i - 7] & 0xFFFFFFFFL)
                    + (s1 & 0xFFFFFFFFL);
            w[i] = (int) sum;
        }


        return w;
    }

    //  4 Этап.  Расширяем расписание до 64 слов.
    //  σ₀ и σ₁ — это «функции перемешивания», которые берут 32‑битное слово, делают над ним циклические сдвиги (rotate) и обычные сдвиги вправо,
    //  после чего объединяют результаты через XOR. Это помогает привнести в сообщение нелинейность и разброс битов.
    private static int sigma0(int x) {
        return Integer.rotateRight(x, 7)
                ^ Integer.rotateRight(x, 18)
                ^ (x >>> 3);
    }
    private static int sigma1(int x) {
        return Integer.rotateRight(x, 17)
                ^ Integer.rotateRight(x, 19)
                ^ (x >>> 10);
    }

    //для этапа 6
    //это «большие» Σ из раундов (другие углы сдвигов).
    private static int bigSigma0(int x) {
        return Integer.rotateRight(x, 2)
                ^ Integer.rotateRight(x, 13)
                ^ Integer.rotateRight(x, 22);
    }
    private static int bigSigma1(int x) {
        return Integer.rotateRight(x, 6)
                ^ Integer.rotateRight(x, 11)
                ^ Integer.rotateRight(x, 25);
    }
    //ch (choose) и maj (majority) — булевы функции, тоже из стандарта.
    private static int ch(int x, int y, int z) {
        return (x & y) ^ (~x & z);
    }
    private static int maj(int x, int y, int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }


    //5 Этап. Основной цикл хеширования
    // Задача метода взять исходные байты, привести их к формату, понятному алгоритму, и прогнать через раунды компрессии.
    // В итоге он возвращает итоговый хеш в виде массива из 32 байтов.
    public byte[] digest(byte[] message){
        //Берём исходные данные и дополняем их по правилам паддинга
        byte[] padded = padMessage(message);
        //Вычисляем количество блоков по 64 байта
        int blockCount = padded.length / BLOCK_SIZE;
        //Инициализируем хеши начальными значениями
        int[] h = Arrays.copyOf(INITIAL_HASHES, INITIAL_HASHES.length);
        byte[] block = new byte[BLOCK_SIZE];
        for (int i = 0; i < blockCount; i++) {
            System.arraycopy(padded, i * BLOCK_SIZE, block, 0, BLOCK_SIZE);
            //формируем массив W[0…63] для каждого блока
            int[] w = prepareMessageSchedule(block);

            //Этап 6
            int a = h[0];
            int b = h[1];
            int c = h[2];
            int d = h[3];
            int e = h[4];
            int f = h[5];
            int g = h[6];
            int hTemp = h[7];

            for (int t = 0; t < 64; t++) {
                long temp1 = (hTemp & 0xFFFFFFFFL)
                        + (bigSigma1(e) & 0xFFFFFFFFL)
                        + (ch(e, f, g) & 0xFFFFFFFFL)
                        + (ROUND_CONSTANTS[t] & 0xFFFFFFFFL)
                        + (w[t] & 0xFFFFFFFFL);

                long temp2 = (bigSigma0(a) & 0xFFFFFFFFL)
                        + (maj(a, b, c) & 0xFFFFFFFFL);

                hTemp = g;
                g = f;
                f = e;
                e = (int) ((d & 0xFFFFFFFFL) + temp1);
                d = c;
                c = b;
                b = a;
                a = (int) ((temp1 + temp2) & 0xFFFFFFFFL);
            }
            h[0] = (int) ((h[0] & 0xFFFFFFFFL) + (a & 0xFFFFFFFFL));
            h[1] = (int) ((h[1] & 0xFFFFFFFFL) + (b & 0xFFFFFFFFL));
            h[2] = (int) ((h[2] & 0xFFFFFFFFL) + (c & 0xFFFFFFFFL));
            h[3] = (int) ((h[3] & 0xFFFFFFFFL) + (d & 0xFFFFFFFFL));
            h[4] = (int) ((h[4] & 0xFFFFFFFFL) + (e & 0xFFFFFFFFL));
            h[5] = (int) ((h[5] & 0xFFFFFFFFL) + (f & 0xFFFFFFFFL));
            h[6] = (int) ((h[6] & 0xFFFFFFFFL) + (g & 0xFFFFFFFFL));
            h[7] = (int) ((h[7] & 0xFFFFFFFFL) + (hTemp & 0xFFFFFFFFL));

        }
        byte[] digest = new byte[DIGEST_LENGTH];
        for (int i = 0; i < h.length; i++) {
            writeIntBigEndian(digest, i * 4, h[i]);
        }
        return digest;
    }

    private static void writeIntBigEndian(byte[] dest, int offset, int value) {
        dest[offset] = (byte) (value >>> 24);
        dest[offset + 1] = (byte) (value >>> 16);
        dest[offset + 2] = (byte) (value >>> 8);
        dest[offset + 3] = (byte) value;
    }








}


