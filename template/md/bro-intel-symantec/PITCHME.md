---
## Real example

![Symantec Distrust](template/img/bro_symantec_distrust_headlines.png)

<div class="reference">Example: /pcap/symantec_certs.pcap</div>
Note:

Symantec ran a sloppy cert business for years and Google and Mozilla called them on it.

Sources:
- Comodo Ad: https://ssl.comodo.com/staytrusted/index.php?ap=SUTSEM2018&gclid=Cj0KCQjwpcLZBRCnARIsAMPBgF3RKegBAakgwl9DB4EXD4vJs9pn4fhFd4KwnPeVU7dlcKx39BGdLcwaAqWhEALw_wcB
- Mozilla Blog: https://blog.mozilla.org/security/2018/03/12/distrust-symantec-tls-certificates/
- The Register article: https://www.theregister.co.uk/2018/02/07/beware_the_coming_chrome_certificate_apocalypse/

---

## Walk-Through

Task: Find all the assets on your network using the dying cert CAs.

@ol

- Find all the root CA certs
- Put them into Bro intel framework
- ...
- ~Profit~ Win!

@olend

Note:

Start here: https://blog.mozilla.org/security/2018/03/12/distrust-symantec-tls-certificates/

Consensus Proposal: https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/FLHRT79e3XE/discussion

CCA DB: https://ccadb.org/

---?code=template/src/bro/intel/bad-symantec-certs.dat&title=Load the data

@[1,2]

---?code=template/src/bro/intel/bad-cert-intel.bro&title=Load the intel

This isn't quite enough. Try to find the definition of `Intel::CERT_HASH` in
the Bro documentation and explain.

---
## Moar Code!!!1

![Moar Cat](template/img/moar-cat.jpg)

Note:

Browse to `/usr/share/bro/policy/frameworks/intel/seen`. Identify where the
certs are "seen".

---

## Bro code for x509 intel
```
event file_hash(f: fa_file, kind: string, hash: string)
    {
    if ( ! f?$info || ! f$info?$x509 || kind != "sha1" )
            return;

    Intel::seen([$indicator=hash,
                 $indicator_type=Intel::CERT_HASH,
                 $f=f,
                 $where=X509::IN_CERT]);
    }
```

---

## But wait, there's more!
```
event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
  {
  if ( /emailAddress=/ in cert$subject )
          {
          local email = sub(cert$subject, /^.*emailAddress=/, "");
          email = sub(email, /,.*$/, "");
          Intel::seen([$indicator=email,
                       $indicator_type=Intel::EMAIL,
                       $f=f,
                       $where=X509::IN_CERT]);
          }

  if ( f$info?$sha1 ) # if the file_hash event was raised before the x509 event...
          {
          Intel::seen([$indicator=f$info$sha1,
                       $indicator_type=Intel::CERT_HASH,
                       $f=f,
                       $where=X509::IN_CERT]);
          }
  }

```
@[1]
@[13-19]

Note:

Why are we "seeing" this cert twice?

---

## Final Piece

```
event file_new(f: fa_file)
{
  Files::add_analyzer(f, Files::ANALYZER_SHA256);
}
```

Note:

This is covered in the Files Framework. You can have it here for free.

Run this example on `/pcap/symantec_certs.pcap`. Run the following:

```
bro -C -r /pcap/symantec_certs.pcap ~/exercises/bro/intel-4/*.bro
``

1. Check `intel.log`
2. Back-reference `id.resp_p` to `answers` in `dns.log` to get the website.
