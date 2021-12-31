package org.esteid.sk;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.Arrays;

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


    @Test
    public void testParseAIA() throws Exception {
        X509CertificateHolder holder = new X509CertificateHolder(CertificateHelpers.pem2crt(getClass().getResourceAsStream("serial-pno.pem")).getEncoded());

        AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.fromExtensions(holder.getExtensions());
        for (AccessDescription accessDescription : authorityInformationAccess.getAccessDescriptions()) {
            // URI for OCSP
            if (accessDescription.getAccessMethod().equals(AccessDescription.id_ad_ocsp) && accessDescription.getAccessLocation().getTagNo() == GeneralName.uniformResourceIdentifier) {
                // This is IA5String
                Assert.assertEquals(ASN1IA5String.getInstance(accessDescription.getAccessLocation().getName()).getString(), "http://aia.sk.ee/esteid2018");
            }
        }
    }
}
