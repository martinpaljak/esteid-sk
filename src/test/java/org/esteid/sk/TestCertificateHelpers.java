package org.esteid.sk;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.stream.Collectors;

public class TestCertificateHelpers {

    @Test
    public void testPNOSerial() throws Exception {
        InputStream in = getClass().getResourceAsStream("serial-pno.pem");
        String pem = String.join("", new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8)).lines().collect(Collectors.toList()));
        Assert.assertEquals(CertificateHelpers.crt2idcode(CertificateHelpers.pem2crt(pem)).get(), "38207162722");
    }

    @Test
    public void testPNOSerialPolicies() throws Exception {
        InputStream in = getClass().getResourceAsStream("serial-pno.pem");
        String pem = String.join("", new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8)).lines().collect(Collectors.toList()));
        Set<String> policies = CertificateHelpers.getPolicies(CertificateHelpers.pem2crt(pem));
        Assert.assertEquals(policies.size(), 2);
        Assert.assertTrue(policies.contains("1.3.6.1.4.1.51361.1.1.1"));
        Assert.assertTrue(policies.contains("0.4.0.2042.1.2"));
    }

    @Test
    public void testNonPNOSerial() throws Exception {
        InputStream in = getClass().getResourceAsStream("sk-auth-ecc.pem");
        String pem = String.join("", new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8)).lines().collect(Collectors.toList()));
        Assert.assertEquals(CertificateHelpers.crt2idcode(CertificateHelpers.pem2crt(pem)).get(), "38207162722");
    }

    @Test
    public void testNoSerial() throws Exception {
        InputStream in = getClass().getResourceAsStream("sk-esteid.pem");
        String pem = String.join("", new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8)).lines().collect(Collectors.toList()));
        Assert.assertFalse(CertificateHelpers.crt2idcode(CertificateHelpers.pem2crt(pem)).isPresent());
    }
}
