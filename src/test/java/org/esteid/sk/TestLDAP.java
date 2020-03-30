package org.esteid.sk;

import org.testng.Assert;
import org.testng.annotations.Test;

public class TestLDAP {
    @Test
    public void testFetch() throws Exception {
        Assert.assertTrue(LDAP.fetch("38207162722").size() > 0);
    }
}
