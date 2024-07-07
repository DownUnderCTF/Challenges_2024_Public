module sirkit(
    byte_num,
    byte_guess,
    guess_valid); 
    input[4:0] byte_num; 
    input[7:0] byte_guess; 
    output wire guess_valid;

    wire [7:0] flag [0:31]; // DUCTF{51r_y35_s1r_c0ec4d}XXXXXXX   padded
    assign flag[0] = "D";
    assign flag[1] = "U";
    assign flag[2] = "C";
    assign flag[3] = "T";
    assign flag[4] = "F";
    assign flag[5] = "{";
    assign flag[6] = "5";
    assign flag[7] = "1";
    assign flag[8] = "r";
    assign flag[9] = "_";
    assign flag[10] = "y";
    assign flag[11] = "3";
    assign flag[12] = "5";
    assign flag[13] = "_";
    assign flag[14] = "s";
    assign flag[15] = "1";
    assign flag[16] = "r";
    assign flag[17] = "_";
    assign flag[18] = "c";
    assign flag[19] = "0";
    assign flag[20] = "e";
    assign flag[21] = "c";
    assign flag[22] = "4";
    assign flag[23] = "d";
    assign flag[24] = "}";
    assign flag[25] = "X";
    assign flag[26] = "X";
    assign flag[27] = "X";
    assign flag[28] = "X";
    assign flag[29] = "X";
    assign flag[30] = "X";
    assign flag[31] = "X";

    assign guess_valid = flag[byte_num] === byte_guess;
endmodule