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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.encoders.Hex;

import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.*;
import java.util.stream.Collectors;

public final class CertificateHelpers {

    // Read: SSH can be done with it.
    public static boolean isCardAuthenticationKey(X509Certificate c) {
        boolean[] ku = c.getKeyUsage();
        // NonRepudiation
        if (ku != null && ku[1] == true)
            return false;
        Map<String, String> m = cert2subjectmap(c);
        if (m.containsKey("O")) {
            if (m.get("O").toUpperCase().equals("ESTEID (MOBIIL-ID)"))
                return false;
            if (m.get("O").toUpperCase().equals("MOBILE-ID"))
                return false;
        }
        return true;
    }

    // Extract meaningful values from subject to a handy map
    public static Map<String, String> cert2subjectmap(X509Certificate c) {
        Map<String, String> m = new HashMap<>();
        try {
            LdapName ldapDN = new LdapName(c.getSubjectX500Principal().getName());
            for (Rdn rdn : ldapDN.getRdns()) {
                if (rdn.getValue() instanceof byte[]) {
                    byte[] v = (byte[]) rdn.getValue();
                    m.put(rdn.getType(), Hex.toHexString(v));
                    if (v[0] == 0x13)
                        m.put(rdn.getType(), new String(Arrays.copyOfRange(v, 2, v[1] + 2), StandardCharsets.US_ASCII));
                    else if (v[0] == 0x0c)
                        m.put(rdn.getType(), new String(Arrays.copyOfRange(v, 2, v[1] + 2), StandardCharsets.UTF_8));
                    else
                        System.out.println(rdn.toString());
                } else if (rdn.getValue() instanceof String) {
                    m.put(rdn.getType(), rdn.getValue().toString());
                } else
                    System.out.println(rdn.toString());
            }
        } catch (InvalidNameException e) {
            e.printStackTrace();
        }
        return m;
    }

    public static Set<String> getPolicies(X509Certificate c) {
        try {
            X509CertificateHolder holder = new X509CertificateHolder(c.getEncoded());
            CertificatePolicies policies = CertificatePolicies.fromExtensions(holder.getExtensions());
            return Arrays.asList(policies.getPolicyInformation()).stream().map(e -> e.getPolicyIdentifier().toString()).collect(Collectors.toSet());
        } catch (IOException | CertificateException e) {
            throw new RuntimeException("Could not parse certificate: " + e.getMessage(), e);
        }
    }

    // Listed in 2.2.3 https://www.skidsolutions.eu/upload/files/SK-CPR-ESTEID2018-EN-v1_2_20200630.pdf
    public static boolean isDigiID(X509Certificate c) {
        return getPolicies(c).contains("1.3.6.1.4.1.51361.1.1.3");
    }

    public static String getCN(X509Certificate c) throws CertificateParsingException {
        try {
            LdapName ldapDN = new LdapName(c.getSubjectX500Principal().getName());
            for (Rdn rdn : ldapDN.getRdns()) {
                if (rdn.getType().equals("CN"))
                    return rdn.getValue().toString();
            }
            // If the certificate does not have CN, make a hash of the certificate
            // This way we always return something if we have a valid certificate
            return new BigInteger(1, MessageDigest.getInstance("SHA-256").digest(c.getEncoded())).toString(16);
        } catch (NamingException | NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new CertificateParsingException("Could not fetch common name from certificate", e);
        }
    }

    public static String crt2pem(X509Certificate c) throws IOException {
        try {
            return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder().encodeToString(c.getEncoded()) + "\n-----END CERTIFICATE-----";
        } catch (CertificateEncodingException e) {
            throw new IOException(e);
        }
    }

    public static boolean isMobileID(X509Certificate cert) {
        if (cert.getSubjectX500Principal().toString().contains("MOBIIL-ID"))
            return true;
        return false;
    }

    public static boolean isDigitalSignatureCertificate(X509Certificate cert) {
        // Check for NonRepudiation flag
        if (!cert.getKeyUsage()[1])
            return false;
        return true;
    }

    public static boolean isCardAuthCertificate(X509Certificate cert) {
        return !isMobileID(cert) && !isDigitalSignatureCertificate(cert);
    }

    public static Collection<X509Certificate> filter_by_algorithm(Collection<X509Certificate> i, String algo) {
        return i.stream().filter(c -> c.getPublicKey().getAlgorithm().equals(algo)).collect(Collectors.toList());
    }

    public static X509Certificate pem2crt(String pem) throws CertificateException {
        pem = pem.replaceFirst("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", "");
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(pem)));
    }

    public static Optional<String> crt2idcode(X509Certificate cert) {
        return Optional.ofNullable(cert2subjectmap(cert).getOrDefault("2.5.4.5", null)).map(e -> e.startsWith("PNOEE-") ? e.substring(6) : e);
    }
}
