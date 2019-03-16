package cafe.cryptography.curve25519;

class StrUtils {
    /**
     * Converts bytes to a hex string.
     *
     * @param raw the byte[] to be converted.
     * @return the hex representation as a string.
     */
    static String bytesToHex(byte[] raw) {
        if (raw == null) {
            return null;
        }
        final StringBuilder hex = new StringBuilder(2 * raw.length);
        for (final byte b : raw) {
            hex.append(Character.forDigit((b & 0xF0) >> 4, 16)).append(Character.forDigit((b & 0x0F), 16));
        }
        return hex.toString();
    }
}
