.PHONY: build clean

build:
	GOOS=js GOARCH=wasm go build -o static/main.wasm wasm/main.go wasm/crypto.go
	cp "$(shell go env GOROOT)/lib/wasm/wasm_exec.js" static/

clean:
	rm -f static/main.wasm static/wasm_exec.js
