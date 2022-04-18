public class App {
    public static void main(String[] args) throws Exception {
        
        int i = 15;     // 00001111
        int j = 27;     // 00011011

        // bitwise OR
        System.out.println(i | j);

        // bitwise AND
        System.out.println(i & j);

        // bitwise XOR
        System.out.println(i ^ j);

        // signed bitshift left
        int shiftAmount = 1;
        System.out.println(i << shiftAmount);

        // signed bitshift right
        System.out.println(i >> shiftAmount);

        // unsigned bitshift right
        System.out.println(i >>> shiftAmount);
    }
}
