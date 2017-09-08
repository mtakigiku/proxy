token=`cat $1`
curl --header "Authorization: Bearer $token" http://localhost:9090/echo -d "hello world" -v
