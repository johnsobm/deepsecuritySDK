# Deep Security unifed SDK

## Requirements
### Software Requirements 
To run this SDK and example scripts, please make sure you have the following installed on your system :
1. Python 2.6 
2. pip install zeep pandas 

Note: If your using a Mac OSX, it is often noted that that python + OpenSSL + MacOS do not play well together. Maye requre updating OpenSSL. 

### DSM Requirements 
1. [Enable SOAP API access and create a user for it in DSM](https://automation.deepsecurity.trendmicro.com/article/11_1/use-the-previous-rest-api#user) Remember the username and password for the script. 
2. [Create an API key (read-only is fine for reports)](https://automation.deepsecurity.trendmicro.com/article/11_1/create-and-manage-api-keys) 

## Setting up
Pick an example from the examples dir to start with. Put in your DSM's information at the top. 
Modify any subsection as your need requires. 

### Run
Execute the script. 


### Notes
You may see error scroll past like: 
Error obtaining Group 19208 with error (401)
Reason: 

You can ignore these. It just means that the requested group is not avaliable and the SDK will try again later. 

As long as the script is executing, let it run. To collect the data from a large DSM may take a couple hours. 

If it crashes, please report it along with the stack trace. 
