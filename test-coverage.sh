#!/bin/bash
echo "mode: set" > acc.out
fail=0

# Install the old cover tool if version is not 1.4 or higher.
if [ -n "$TRAVIS_GO_VERSION" ] && [[ "$TRAVIS_GO_VERSION" < "go1.4" ]]; then
  go get -u code.google.com/p/go.tools/cmd/cover
fi

# Standard go tooling behavior is to ignore dirs with leading underscors
for dir in $(find . -maxdepth 10 -not -path './cmd/*' -not -path './.git*' -not -path '*/_*' -type d); do
  if ls $dir/*.go &> /dev/null; then
    go test -v -coverprofile=profile.out $dir || fail=1
    if [ -f profile.out ]; then
      cat profile.out | grep -v "mode: set" >> acc.out
      rm profile.out
    fi
  fi
done

# Failures have incomplete results, so don't send
if [ -n "$COVERALLS_TOKEN" ] && [ "$fail" -eq 0 ]; then
  $HOME/gopath/bin/goveralls -v -coverprofile=acc.out -service travis-ci -repotoken $COVERALLS_TOKEN || fail=1
fi

rm -f acc.out
exit $fail
