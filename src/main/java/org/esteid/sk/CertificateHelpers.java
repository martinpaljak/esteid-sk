/**
 * Copyright (c) 2017-2020 Martin Paljak
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.esteid.sk;

import org.bouncycastle.cert.X509CertificateHolder;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.stream.Collectors;

public final class CertificateHelpers {

    public static X509CertificateHolder crt2holder(X509Certificate c) {
        try {
            return new X509CertificateHolder(c.getEncoded());
        } catch (CertificateException | IOException e) {
            throw new RuntimeException("Could not parse certificate: " + e.getMessage(), e);
        }
    }

    public static String crt2pem(X509Certificate c) throws IOException {
        try {
            return bytes2pem(c.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IOException(e);
        }
    }

    public static String bytes2pem(byte[] bytes) {
        return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder().encodeToString(bytes) + "\n-----END CERTIFICATE-----";
    }

    public static Collection<X509Certificate> filter_by_algorithm(Collection<X509Certificate> i, String algo) {
        return i.stream().filter(c -> c.getPublicKey().getAlgorithm().equals(algo)).collect(Collectors.toList());
    }

    static X509Certificate bytes2crt(byte[] c) {
        try {
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            return (X509Certificate) f.generateCertificate(new ByteArrayInputStream(c));
        } catch (CertificateException e) {
            throw new RuntimeException("Bad certificate in system: " + e.getMessage(), e);
        }
    }

    public static X509Certificate pem2crt(String pem) throws CertificateException {
        pem = pem.replaceFirst("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", "");
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(pem)));
    }

    public static X509Certificate pem2crt(InputStream in) throws CertificateException {
        String pem = String.join("", new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8)).lines().collect(Collectors.toList()));
        return pem2crt(pem);
    }
}
