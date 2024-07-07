module sirkit_tb;
    reg [4:0] idx;
    reg [7:0] guess;
    wire guess_valid;

    integer g;
    integer i;

    sirkit dut(
        .byte_num(idx),
        .byte_guess(guess),
        .guess_valid(guess_valid)
    );

    initial begin
        for (i=0; i < 32; i=i+1) begin
            idx <= i;
            for(g=0; g < 256; g=g+1) begin
                guess <= g;
                #1; // wait some time
            end
        end
    end

    always @(posedge guess_valid) begin
        $display("flag[%d] = %s", idx, guess);
    end
endmodule