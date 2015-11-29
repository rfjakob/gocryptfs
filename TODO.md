* Add test filesystem for "--masterkey" containing an "It works!" file
* Add fcntl file locking to make multiple concurrent mounts safe
 * add test case
* Add "--pwfile" parameter that reads the password from a file
 * Use that for additional test cases
* Find out why "./gocryptfs -version" takes 170ms.
