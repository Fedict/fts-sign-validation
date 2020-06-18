# Python Test framework

The test framework has been built using a basic python lib called requests and behave. Requests is used in order to fire and validate the API call response. While behave is used as the python variant of cucumber. In this sense the tests can be fired with the following command

`behave --tags=wip`

With these tags it's possible to fire different and multiple tests at the same time. For instance in this framework the tag active is used in order to fire all the tests.

Behave works like cucumber, in the sense that there are feature files and step files. These feature files will link to the different steps, while the steps themselves refer to the actual python code. The basic guidelines here are that there is no or very little logic in the steps. These are purely to pass on variables and activating the required functions. One major difference between cucumber and behave is the integration of the context. Behave by default has a context variable that can be used to pass parameters over different steps. This added functionality is gold in terms of test validation.

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
