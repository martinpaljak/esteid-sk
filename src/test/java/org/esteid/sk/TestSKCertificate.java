package org.esteid.sk;

import org.testng.Assert;
import org.testng.annotations.Test;

public class TestSKCertificate {

    @Test
    public void testPNOSerial() throws Exception {
        SKCertificate c = SKCertificate.fromPEM(getClass().getResourceAsStream("serial-pno.pem"));
        Assert.assertEquals(c.getPersonalCode(), "38207162722");
    }

    @Test
    public void testPNOSerialCN() {
        SKCertificate c = SKCertificate.fromPEM(getClass().getResourceAsStream("utf8.pem"));
        Assert.assertEquals(c.getCN(), "VAHER,MÄRTEN,38206180214");
    }

    @Test
    public void testNonPNOSerial() {
        SKCertificate c = SKCertificate.fromPEM(getClass().getResourceAsStream("sk-auth-ecc.pem"));
        Assert.assertEquals(c.getPersonalCode(), "38207162722");
    }

    @Test(expectedExceptions = IllegalStateException.class)
    public void testNoSerial() throws Exception {
        SKCertificate c = SKCertificate.fromPEM(getClass().getResourceAsStream("sk-esteid.pem"));
        c.getPersonalCode();
    }

    @Test
    public void testToJava() {
        SKCertificate c = SKCertificate.fromPEM(getClass().getResourceAsStream("serial-pno.pem"));
        c.toJava();
    }
}
