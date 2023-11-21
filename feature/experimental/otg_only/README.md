FOR SW ports
1. cd ~/featureprofiles/feature/experimental/otg_only
2. Deploy the b2b topology with "kne_cli create otgb2b.textproto"
3. Run the test with 
    go test -v otgb2b_test.go -kne-topo otgb2b.textproto -testbed otgb2b.testbed



FOR HW ports
1. cd ~/featureprofiles/feature/experimental/otg_only
2. Deploy the 3 containers used in otg-hw setup with:
    docker compose -f docker-compose.yml --profile all up -d
3. Modify the otghw.binding file to match your setup.
4. Run the test with: 
    go test -v otgb2b_test.go -binding otghw.binding -testbed otgb2b.testbed
5. Remove the 3 containers used in otg-hw setup with:
    docker compose -f docker-compose.yml --profile all down

FOR UHD Ports
1. setup should already be deployed with b2b ports
2. Modify the otgb2b-uhd.binding file to match your setup.
3. Run the Test with:
 go test -v otgb2b_test.go -binding otghw.binding -testbed otgb2b.testbed
