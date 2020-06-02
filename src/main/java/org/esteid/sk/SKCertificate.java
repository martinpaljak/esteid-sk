/**
 * Copyright (c) 2020-present Martin Paljak
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
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

public class SKCertificate {
    final X509CertificateHolder c;

    public static SKCertificate from(X509Certificate c) {
        return new SKCertificate(CertificateHelpers.crt2holder(c));
    }

    public static SKCertificate fromPEM(String pem) {
        try {
            return from(CertificateHelpers.pem2crt(pem));
        } catch (CertificateException e) {
            throw new RuntimeException("Could not parse certificate PEM: " + e.getMessage(), e);
        }
    }

    public static SKCertificate fromPEM(InputStream pem) {
        try {
            return from(CertificateHelpers.pem2crt(pem));
        } catch (CertificateException e) {
            throw new RuntimeException("Could not parse certificate PEM: " + e.getMessage(), e);
        }
    }

    public static SKCertificate from(byte[] bytes) {
        try {
            return new SKCertificate(new X509CertificateHolder(bytes));
        } catch (IOException e) {
            throw new RuntimeException("Could not parse certificate bytes: " + e.getMessage(), e);
        }
    }

    public SKCertificate(X509CertificateHolder c) {
        this.c = c;
    }

    public byte[] getBytes() {
        try {
            return c.getEncoded();
        } catch (IOException e) {
            throw new RuntimeException("Could not encode certificate: " + e.getMessage(), e);
        }
    }

    public X509Certificate toJava() {
        try {
            return new JcaX509CertificateConverter().getCertificate(c);
        } catch (CertificateException e) {
            throw new IllegalStateException("Can not convert certificate: " + e.getMessage(), e);
        }
    }

    public String toPEM() {
        return CertificateHelpers.bytes2pem(getBytes());
    }

    public byte[] sha256() {
        try {
            return MessageDigest.getInstance("SHA-256").digest(getBytes());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("No SHA-256!", e);
        }
    }

    Optional<String> getSingle(ASN1ObjectIdentifier oid) {
        RDN rdn[] = c.getSubject().getRDNs(oid);
        if (rdn.length == 0)
            return Optional.empty();
        if (rdn.length != 1)
            throw new IllegalStateException("Expect single " + oid + ": " + c.getSubject());
        return Optional.of(rdn[0].getFirst().getValue().toString());
    }

    public String getCN() {
        return getSingle(BCStyle.CN).orElseThrow(() -> new IllegalStateException("No CN: " + c.getSubject()));
    }

    public Optional<String> getO() {
        return getSingle(BCStyle.O);
    }

    public Optional<String> getOU() {
        return getSingle(BCStyle.OU);
    }

    public String getPersonalCode() {
        return getSingle(BCStyle.SERIALNUMBER).map(sn -> sn.startsWith("PNOEE-") ? sn.substring(6) : sn).orElseThrow(() -> new IllegalStateException("No serialNumber in certificate: " + c.getSubject()));
    }

    public Set<String> getPolicies() {
        // get all policy oid-s
        CertificatePolicies policies = CertificatePolicies.fromExtensions(c.getExtensions());
        return Arrays.asList(policies.getPolicyInformation()).stream().map(e -> e.getPolicyIdentifier().toString()).collect(Collectors.toSet());
    }

    public boolean hasPolicyOrPrefix(String oid) {
        return getPolicies().stream().filter(e -> e.startsWith(oid)).count() > 0;
    }

    static HashMap<String, String> oids = new HashMap<>();

    static {
        // https://www.skidsolutions.eu/upload/files/SK-CPR-ESTEID2018-EN-v1_2_20200630.pdf 2.2.3
        oids.put("1.3.6.1.4.1.51361.1.1.1", "ID card");
        oids.put("1.3.6.1.4.1.51361.1.1.2", "EU citizen ID card");
        oids.put("1.3.6.1.4.1.51361.1.1.3", "Digi ID");
        oids.put("1.3.6.1.4.1.51361.1.1.4", "e-resident ID");
        oids.put("1.3.6.1.4.1.51361.1.1.5", "Resident ID");
        oids.put("1.3.6.1.4.1.51361.1.1.6", "Resident ID");
        oids.put("1.3.6.1.4.1.51455.1.1.1", "Diplomatic ID");
    }

    public String cardType() {
        Optional<Map.Entry<String, String>> newStyle = oids.entrySet().stream().filter(e -> hasPolicyOrPrefix(e.getKey())).findFirst();
        if (newStyle.isPresent())
            return newStyle.get().getValue();

        if (hasPolicyOrPrefix("1.3.6.1.4.1.10015.1.1"))
            return "ID card";
        if (hasPolicyOrPrefix("1.3.6.1.4.1.10015.1.2")) {
            if (getO().equals(Optional.of("ESTEID (DIGI-ID E-RESIDENT)")))
                return "e-resident ID";
            return "Digi ID";
        }
        if (hasPolicyOrPrefix("1.3.6.1.4.1.10015.1.3")) {
            return "Mobile ID";
        }
        System.err.println("Unknown SK certificate card type: " + getPolicies() + ", " + c.getSubject());
        return null;
    }

    public boolean isMobileID() {
        return hasPolicyOrPrefix("1.3.6.1.4.1.10015.1.3") || getO().equals(Optional.of("ESTEID (MOBIIL-ID)"));
    }

    public boolean isSigningCertificate() {
        return getPolicies().contains("0.4.0.194112.1.2") || getOU().equals(Optional.of("digital signature"));
    }

    public boolean isAuthenticationCertificate() {
        return getPolicies().contains("0.4.0.2042.1.2") || getOU().equals(Optional.of("authentication"));
    }

    public boolean isCardAuthenticationCertificate() {
        return isAuthenticationCertificate() && !isMobileID();
    }

    public String describe() {
        return String.format("%s %s (%s)", getCN(), cardType(), isSigningCertificate() ? "sign" : "auth");
    }
}
