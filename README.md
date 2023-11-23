# aciClient

![PyPi](https://img.shields.io/pypi/v/aciClient)

A python wrapper to the Cisco ACI REST-API.

## Python Version

We support Python 3.6 and up. Python 2 is not supported and there is no plan to add support for it.

## Installation
``pip install aciclient``

## Installation for Developing
```
git clone https://github.com/netcloud/aciclient.git
pip install -r requirements.txt
python setup.py develop
```

## Usage

### Initialisation

### Username/password
```python
import logging
from aciclient import AciClient, AciCredentialsPassword

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

credentials = AciCredentialsPassword(ip="devnetsandboxdc.cisco.com", username="admin", password="ciscopstd")

with AciClient(credentials, logger=logger)
    aciclient.getJson(uri)
    aciclient.postJson(config)
    aciclient.deleteMo(dn)
    
```

For automatic authentication token refresh you can set variable ```refresh``` to True

```python
aciclient = aciClient.ACI(apic_hostname, apic_username, apic_password, refresh=True)    
```


### Certificate/signature
```python
import aciClient
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

aciclient = aciClient.ACICert(apic_hostname, path_to_privatekey_file, certificate_dn)

try:
    aciclient.getJson(uri)
    aciclient.postJson(config)
    aciclient.deleteMo(dn)
except Exception as e:
    logger.exception("Stack Trace")
```

## Examples

### get config without params
```python
tenants = aciclient.getJson('class/fvTenant')
for tenant in tenants.data:
    print(tenant["fvTenant"]["attributes"]["dn"])
```

### get config with params
```python
params = {"order-by": "fvTenant.dn|asc"}
tenants = aciclient.getJson('class/fvTenant', ep_params=params)
for mo in tenants:
    print(f'tenant DN: {mo["fvTenant"]["attributes"]["dn"]}')
```

### post payload without path
```python
payload = {
 "fvTenant": {
  "attributes": {
   "dn": "uni/tn-XYZ"
  }
 }
}

aciclient.postJson(payload)
```

### delete MOs
```python
aciclient.deleteMo('uni/tn-XYZ')
```

### create snapshot
You can specify a tenant in variable ```target_dn``` or not provide any to do a fabric-wide snapshot.
```python
aciclient.snapshot(description='test', target_dn='/uni/tn-test')
```

## Testing

```
pip install -r requirements.txt
python -m pytest
```
## Contributing

Please read [CONTRIBUTING.md](https://github.com/netcloud/aciClient/blob/master/CONTRIBUTING.md) for details on our code 
of conduct, and the process for submitting pull requests to this project.

## Authors

* **Marcel Zehnder** - *Initial work*
* **Andreas Graber** - *Migration to open source*
* **Richard Strnad** - *Paginagtion for large requests, various small stuff*
* **Dario Kaelin** - *Rewrite 2.0*

## License

This project is licensed under MIT - see the [LICENSE.md](https://github.com/netcloud/aciClient/blob/master/LICENSE.md) file for details. 
