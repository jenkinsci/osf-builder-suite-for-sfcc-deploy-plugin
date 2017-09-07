package org.jenkinsci.plugins.osfbuildersuiteforsfcc.deploy.impl;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import hudson.Extension;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.deploy.TwoFactorAuthCredentials;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

public class TwoFactorAuthCredentialsImpl extends BaseStandardCredentials implements TwoFactorAuthCredentials {

    private static final long serialVersionUID = 1L;

    private final String serverCertificate;
    private final String clientCertificate;
    private final String clientPrivateKey;

    @DataBoundConstructor
    public TwoFactorAuthCredentialsImpl(@CheckForNull CredentialsScope scope, @CheckForNull String id,
                                        @CheckForNull String description, String serverCertificate,
                                        String clientCertificate, String clientPrivateKey) {

        super(scope, id, description);

        this.serverCertificate = serverCertificate;
        this.clientCertificate = clientCertificate;
        this.clientPrivateKey = clientPrivateKey;
    }

    @Override
    public String getServerCertificate() {
        return serverCertificate;
    }

    @Override
    public String getClientCertificate() {
        return clientCertificate;
    }

    @Override
    public String getClientPrivateKey() {
        return clientPrivateKey;
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {
        @Nonnull
        @Override
        public String getDisplayName() {
            return "OSF Builder Suite Two Factor Auth";
        }
    }
}
