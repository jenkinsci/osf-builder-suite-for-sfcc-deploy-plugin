package org.jenkinsci.plugins.osfbuildersuiteforsfcc.deploy;

import com.cloudbees.plugins.credentials.CredentialsNameProvider;
import com.cloudbees.plugins.credentials.NameWith;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import org.apache.commons.lang3.StringUtils;

import javax.annotation.Nonnull;

@NameWith(TwoFactorAuthCredentials.NameProvider.class)
public interface TwoFactorAuthCredentials extends StandardCredentials {
    String getServerCertificate();
    String getClientCertificate();
    String getClientPrivateKey();

    class NameProvider extends CredentialsNameProvider<TwoFactorAuthCredentials> {
        @Nonnull
        @Override
        public String getName(@Nonnull TwoFactorAuthCredentials credentials) {
            String description = StringUtils.trim(credentials.getDescription());
            if (StringUtils.isNotEmpty(description)) {
                return description;
            }

            return credentials.getId();
        }
    }
}
