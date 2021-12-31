package org.esteid.sk;

import org.testng.Assert;
import org.testng.SkipException;
import org.testng.annotations.Test;

public class TestLDAP {

    static boolean isIDE() {
        return System.getProperty("java.class.path").contains("idea_rt.jar");
    }

    @Test
    public void testFetch() throws Exception {
        if (!isIDE())
            throw new SkipException("Not interactive");
        Assert.assertTrue(LDAP.fetch("38207162722").size() > 0);
    }
}
