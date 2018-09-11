#
# Copyright (c) 2016-2018 RockNSM.
#
# This file is part of RockNSM
# (see http://rocknsm.io).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

@load frameworks/intel/seen

# Ensure we SHA256 all the things, but especially the x509 certs
event file_new(f: fa_file)
        {
        Files::add_analyzer(f, Files::ANALYZER_SHA256);
        }

# Observe x509 SHA256 hashes
event file_hash(f: fa_file, kind: string, hash: string)
        {
        if ( ! f?$info || ! f$info?$x509 || kind != "sha256" )
                return;

        Intel::seen([$indicator=hash,
                     $indicator_type=Intel::CERT_HASH,
                     $f=f,
                     $where=X509::IN_CERT]);
        }

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
        {
        if ( f$info?$sha256 ) # if the file_hash event was raised before the x509 event...
                {
                Intel::seen([$indicator=f$info$sha256,
                             $indicator_type=Intel::CERT_HASH,
                             $f=f,
                             $where=X509::IN_CERT]);
                }
        }
