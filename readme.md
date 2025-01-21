# asndb

query [iptoasn.com](https://iptoasn.com/) dataset, but serialized under optimized cache format. alternative to [jedisct1/iptoasn-webservice](https://github.com/jedisct1/iptoasn-webservice)

optimized query that brings a single query internally took ~~_4µs_~~ _2µs_. under load (a bit) 1000cps, ~~70krps~~ 75krps at 10ms.

```
Time to load TSV: 311.2782ms
Time to save binary file: 60.641ms
Time to load from binary file: 87.4464ms
```

update:

- introduce new query system stolen from `iptoasn-webservice`
- whole-content hashing is under maintenance
