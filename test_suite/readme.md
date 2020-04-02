# Python Test framework

## Test code

## Locust performance testing

## Troubleshooting Options

The first option will print the full request in a txt file called requests. This is easier for reporting bugs

```python
from requests_toolbelt.utils import dump

json_file = json.dumps(json_request)
f = open("request.txt", "w+")
f.write(json_file)
```

The next one will print the full response of the request

```python
from requests_toolbelt.utils import dump

data = dump.dump_all(req)
print(data.decode("utf-8"))
```
