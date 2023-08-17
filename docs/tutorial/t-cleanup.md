# Cleanup and extra info
This is part of the [TLS Certificates Operator Tutorial](/t/tls-certificates-operator-tutorial-overview/11605). Please refer to this page for more information and the overview of the content.

## Next Steps
In this tutorial we've successfully deployed TLS Certificates Operator, configured certificates and provided them to another application via relation.
You may now keep your TLS Certificates Operator deployment running and write to the database or remove it entirely using the steps in the following section. If you're looking for what to do next you can:
- [Report](https://github.com/canonical/tls-certificates-operator/issues) any problems you encountered.
- [Give us your feedback](https://chat.charmhub.io/charmhub/channels/telco).
- [Contribute to the code base](https://github.com/canonical/tls-certificates-operator)

## Remove and cleanup environment
If you're done with testing and would like to free up resources on your machine, just remove Multipass VM.
*Warning: when you remove VM as shown below you will lose all the data in TLS Certificates Operator and any other applications inside Multipass VM!*
```shell
multipass delete --purge my-vm
```