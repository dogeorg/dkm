module code.dogecoin.org/dkm

require code.dogecoin.org/governor v1.0.1

require (
	code.dogecoin.org/gossip v0.0.7
	github.com/mattn/go-sqlite3 v1.14.22
	golang.org/x/crypto v0.26.0
)

require golang.org/x/sys v0.23.0 // indirect

// until radicle supports canonical tags
replace code.dogecoin.org/governor => github.com/dogeorg/governor v1.0.1

replace code.dogecoin.org/gossip => github.com/dogeorg/gossip v0.0.7

go 1.20
