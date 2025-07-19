# 1.0.0

Initial Release and foundation, still somethings to work out. 


# 1.1.0 

- Moved from homegrown parsing to `letters`.
- Fixed an issue on refresh we'd request a new cert, which caused the domain to get ratelimited. We know use a EBS to store all `acme.sh` related files (cert, account.conf, etc)
- Added `go-proxyproto` to handle Proxy and be able to properly verify SPF.
