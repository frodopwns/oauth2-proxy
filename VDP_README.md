# Build and push Docker image

Please fork the repo and clone into your `$GOPATH`.

```bash
cd $GOPATH/src/github.com # Create this directory if it doesn't exist
git clone git@gitlab.eng.vmware.com/csp/oauth2-proxy pusher/oauth2_proxy
make push-image TAG=$(make guess-tag)
```
