all: build
generate:
	./generate.py -f flag.txt -s main.rs -o src/main.rs

build: generate
	cargo build --release

test:
	cat flag.txt | ./target/release/rusty_vault | grep 'Congratulations'