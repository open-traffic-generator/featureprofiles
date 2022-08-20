cd ~/featureprofiles/feature/experimental/ate_only
Change ateb2b.binding to match your environment as the test will assume they are b2b connected
go test -v ateb2b_test.go -binding ateb2b.binding -testbed ateb2b.testbed
