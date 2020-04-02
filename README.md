# aws-kms-csr

Create a CSR based on your keys stored in AWS KMS. This isn't even that interesting, but I had a requirement to create a PCKS10 CSR from keys stored in Amazon KMS, and google wasn't my friend that day, so I spent a hour doing this.

The end result is that you're signing the CSR using Amazon; the private key never leaves KMS; so everyone's happy right?

There are no tests; I'm using Java *even though I probably don't need to*; but it's all wrapped up nicely in a gradle task. The source code isn't even that clever; all the hard work has been done by bouncycastle + AWS.

## Quickstart...

* Assumes that you have pre-configured your environment to be able to access KWS (i.e. ~/.aws/credentials is good to go, or the appropriate environment variables are set).

* Create a build.properties file
```
$ cat build.properties
kms.keyId="alias/my alias in KMS" or the UUID.

# This stuff is optional and will be "defaulted"
csr.outputFile=./build/the-output-file
csr.commonName=my.name@myCompany.com
csr.organisationalUnit=MyOrganisationalUnit
csr.organisation=MyOrganisation
csr.locality=MyTown
csr.stateOrProvinceName=MyState
csr.countryName=GB
```

* ./gradlew buildCSR
* You will see a file that looks that looks like a CSR (unless you have overridden it, it will be in `./build/my-csr.csr`)
* You can check whether other things recognise it as a CSR by searching for something that allows you to view CSRs (e.g. use the search term "view csr", and you'll find a bunch of online locations where you can cut and paste that file to verify it).
