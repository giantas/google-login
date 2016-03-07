# google-login

Here's a simple python script that logs in to your Google account and
saves the cookies that you can then use with curl, python-requests or
whatever.


## Dependencies

We use buildout to handle all the dependencies.  Just run:

```shell
python bootstrap.py
./bin/buildout
export PATH=$PWD/bin:$PATH
```


## Example

Put your Google credentials in your `$HOME/.netrc` file:

    machine google.com login example@gmail.com password examplepassword

Then run the following command on the command line:

    ./bin/python googlelogin.py cookies.txt

Next, use that cookies.txt with curl, wget or whatever.

### Why didn't you create a normal python package on pypi?

I use selenium and phantomjs for the Google login which requires nodejs so a
pure python solution wouldn't work.  Instead of a standard python egg
installable via pip, I use buildout.
