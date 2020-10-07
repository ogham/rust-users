all: build test
all-release: build-release test-release

# compiles the code
build:
    cargo +1.31.0 build
    cargo +stable build

# compiles the code in release mode
build-release:
    cargo +1.31.0 build --release --verbose
    cargo +stable build --release --verbose

# runs unit tests
test:
    cargo +1.31.0 test --all -- --quiet
    cargo +stable test --all -- --quiet

# runs unit tests in release mode
test-release:
    cargo +1.31.0 test --all --release --verbose
    cargo +stable test --all --release --verbose
