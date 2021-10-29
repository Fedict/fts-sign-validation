# AES key handling

For creating signing tokens, the sign/validation backend uses AES keys
that are randomly generated once every 5 hours. The key to *create* new
tokens is *never* loaded from anywhere, it is always generated locally;
however, these keys are written to the `keys` subdirectory of a private
bucket (i.e., not any of the customer buckets) on the S3 service
(minio).

The keys are handled through the
`com.zetes.projects.bosa.signandvalidation.service.ObjectStorageService`
and the `com.zetes.projects.bosa.signandvalidation.model.StoredKey`
classes. The former provides two functions: `getKid()`, which returns
the KeyID (`kid`) for the currently-active key (generating one if none
has been generated before, or if the currently-active key is too old and
a new one is required), and `getKeyForId(String)`, which takes the `kid`
as an argument and returns the full AES key (loading it from the S3
storage if required). The latter is an object that is meant mostly as a
container for allowing easy serialization and deserialization into JSON
representations.

The two classes have the following methods that are relevant to key
handling:

## StoredKey

### Constructor

Generates a new random AES key.

### Encoded property

This property (i.e., the `getEncoded()` and `setEncoded(byte[])`
methods) represents the AES raw data. It is used only for the JSON
representation.

### isTooOld()

This method will return `true` 5 hours after the key has been generated.

### Kid property

Generated as 9 random bytes when the key is created. Used as the key ID
(hence, `kid`). `setKid(String)` and `getKid()` methods.

## ObjectStorageService

Note that the ObjectStorageService is a central API point in the
sign/validation service for all contact with the S3 service; as such, it
provides more than just key handling services.

### getKid()

This method uses the following algorithm:

- If there is a currently-active key (a `StoredKey` object, and its
  `isTooOld()` method returns false), return its `kid`.
- If either of those two conditions does not hold, create a new
  `StoredKey` object (whose constructor generates a new AES key -- see
  above), store the JSON representation of that object into a file with
  the name `keys/` + the key's kid + `.json` into the private bucket on
  the object store, store the StoredKey into the internal `kid` -&gt;
  `StoredKey` Map, then return the `kid`.

### getKeyById(String)

This method uses the following algorithm:

- If the internal `kid` -&gt; `StoredKey` Map has an entry for the given
  `kid`, returns the StoredKey from the Map.
- If no such entry exists, download the `keys/` + the given KeyID +
  `.json` from the private bucket on the object store, deserialize it,
  and add it to the Map, then return the object.

## Effects

The above-described methods cooperate to have the following effect:

- No key will be used for longer than 5 hours, and their JSON
  representation will be stored in S3 for other containers to be found.
- The first time a new key is seen by a particular backend container,
  that container will load it from the S3 storage.
- Keys that are older than 10 hours should never be seen in the wild and
  can be removed from the private bucket.
