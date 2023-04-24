# Grumble
      ________                   ___.   .__
     /  _____/______ __ __  _____\_ |__ |  |   ____
    /   \  __\_  __ \  |  \/     \| __ \|  | _/ __ \
    \    \_\  \  | \/  |  /  Y Y  \ \_\ \  |_\  ___/
     \______  /__|  |____/|__|_|  /___  /____/\___  >
            \/                  \/    \/          \/

## Installation

```
# Clone this repo to somewhere
git clone https://github.com/open-ch/grumble
cd grumble

# Install grumble
go install ./...

# The binary should be in $GOPATH/bin
ls `go env GOPATH`/bin
```

## Configuration

We use viper to store the config so in order of preference we will use:
1. Flag values (where applicable)
2. ENV variable
3. Value in `.grumble.config.yaml`

## License

Please see LICENSE.
