1. cd ~/featureprofiles/feature/experimental/otg_only
2. Deploy the b2b topology with "kne_cli create otgb2b.textproto"
3. Create your own testbed.kne.yml file:

cat >testbed.kne.yml << EOF
username: admin
password: admin
topology: $PWD/otgb2b.textproto
cli: $HOME/go/bin/kne_cli
EOF

4. go test -v otgb2b_test.go -kne-config testbed.kne.yml -testbed otgb2b.testbed
