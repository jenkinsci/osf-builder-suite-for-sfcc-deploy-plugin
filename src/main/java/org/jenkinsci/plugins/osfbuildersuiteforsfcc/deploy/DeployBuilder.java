package org.jenkinsci.plugins.osfbuildersuiteforsfcc.deploy;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.URIRequirementBuilder;
import hudson.AbortException;
import hudson.Launcher;
import hudson.Extension;
import hudson.FilePath;
import hudson.model.*;
import hudson.model.queue.Tasks;
import hudson.remoting.VirtualChannel;
import hudson.security.ACL;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import hudson.util.ListBoxModel;
import jenkins.security.MasterToSlaveCallable;
import jenkins.tasks.SimpleBuildStep;
import net.sf.json.JSONObject;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.http.*;
import org.apache.http.Header;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.GzipDecompressingEntity;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.*;
import org.apache.http.config.ConnectionConfig;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.FileEntity;
import org.apache.http.impl.client.*;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.codehaus.plexus.util.MatchPattern;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.credentials.TwoFactorAuthCredentials;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.credentials.BusinessManagerAuthCredentials;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.deploy.repeatable.ExcludePattern;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.deploy.repeatable.SourcePath;
import org.jenkinsci.plugins.tokenmacro.MacroEvaluationException;
import org.jenkinsci.plugins.tokenmacro.TokenMacro;
import org.kohsuke.stapler.*;
import org.zeroturnaround.zip.ByteSource;
import org.zeroturnaround.zip.ZipEntrySource;
import org.zeroturnaround.zip.ZipUtil;

import javax.annotation.Nonnull;
import javax.net.ssl.SSLContext;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


@SuppressWarnings("unused")
public class DeployBuilder extends Builder implements SimpleBuildStep {

    private String hostname;
    private String bmCredentialsId;
    private String tfCredentialsId;
    private String buildVersion;
    private Boolean createBuildInfoCartridge;
    private Boolean activateBuild;
    private List<SourcePath> sourcePaths;
    private String tempDirectory;

    @DataBoundConstructor
    public DeployBuilder(
            String hostname,
            String bmCredentialsId,
            String tfCredentialsId,
            String buildVersion,
            Boolean createBuildInfoCartridge,
            Boolean activateBuild,
            List<SourcePath> sourcePaths,
            String tempDirectory) {

        this.hostname = hostname;
        this.bmCredentialsId = bmCredentialsId;
        this.tfCredentialsId = tfCredentialsId;
        this.buildVersion = buildVersion;
        this.createBuildInfoCartridge = createBuildInfoCartridge;
        this.activateBuild = activateBuild;
        this.sourcePaths = sourcePaths;
        this.tempDirectory = tempDirectory;
    }

    @SuppressWarnings("unused")
    public String getHostname() {
        return hostname;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    @SuppressWarnings("unused")
    public String getBmCredentialsId() {
        return bmCredentialsId;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setBmCredentialsId(String bmCredentialsId) {
        this.bmCredentialsId = StringUtils.trim(bmCredentialsId);
    }

    @SuppressWarnings("unused")
    public String getTfCredentialsId() {
        return tfCredentialsId;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setTfCredentialsId(String tfCredentialsId) {
        this.tfCredentialsId = StringUtils.trim(tfCredentialsId);
    }

    @SuppressWarnings("unused")
    public String getBuildVersion() {
        return buildVersion;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setBuildVersion(String buildVersion) {
        this.buildVersion = buildVersion;
    }

    @SuppressWarnings("unused")
    public Boolean getCreateBuildInfoCartridge() {
        return createBuildInfoCartridge;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setCreateBuildInfoCartridge(Boolean createBuildInfoCartridge) {
        this.createBuildInfoCartridge = createBuildInfoCartridge;
    }

    @SuppressWarnings("unused")
    public Boolean getActivateBuild() {
        return activateBuild;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setActivateBuild(Boolean activateBuild) {
        this.activateBuild = activateBuild;
    }

    @SuppressWarnings("unused")
    public List<SourcePath> getSourcePaths() {
        return sourcePaths;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setSourcePaths(List<SourcePath> sourcePaths) {
        this.sourcePaths = sourcePaths;
    }

    @SuppressWarnings("unused")
    public String getTempDirectory() {
        return tempDirectory;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setTempDirectory(String tempDirectory) {
        this.tempDirectory = tempDirectory;
    }

    private String getBuildCause(Run<?, ?> build) {
        List<Cause> buildCauses = build.getCauses();

        if (!buildCauses.isEmpty()) {
            return buildCauses.get(0).getShortDescription();
        }

        return "Unknown";
    }

    @Override
    public void perform(
            @Nonnull Run<?, ?> build,
            @Nonnull FilePath workspace,
            @Nonnull Launcher launcher,
            @Nonnull TaskListener listener) throws InterruptedException, IOException {

        PrintStream logger = listener.getLogger();

        logger.println();
        logger.println(String.format("--[B: %s]--", getDescriptor().getDisplayName()));
        logger.println();

        String expandedHostname;
        try {
            expandedHostname = TokenMacro.expandAll(build, workspace, listener, hostname);
        } catch (MacroEvaluationException e) {
            AbortException abortException = new AbortException("Exception thrown while expanding the hostname!");
            abortException.initCause(e);
            throw abortException;
        }

        BusinessManagerAuthCredentials bmCredentials = null;
        if (StringUtils.isNotEmpty(bmCredentialsId)) {
            bmCredentials = com.cloudbees.plugins.credentials.CredentialsProvider.findCredentialById(
                    bmCredentialsId,
                    BusinessManagerAuthCredentials.class,
                    build, URIRequirementBuilder.create().build()
            );
        }

        if (bmCredentials != null) {
            com.cloudbees.plugins.credentials.CredentialsProvider.track(build, bmCredentials);
        }

        TwoFactorAuthCredentials tfCredentials = null;
        if (StringUtils.isNotEmpty(tfCredentialsId)) {
            tfCredentials = com.cloudbees.plugins.credentials.CredentialsProvider.findCredentialById(
                    tfCredentialsId,
                    TwoFactorAuthCredentials.class,
                    build, URIRequirementBuilder.create().build()
            );
        }

        if (tfCredentials != null) {
            com.cloudbees.plugins.credentials.CredentialsProvider.track(build, tfCredentials);
        }

        String expandedBuildVersion;
        try {
            expandedBuildVersion = TokenMacro.expandAll(build, workspace, listener, buildVersion);
        } catch (MacroEvaluationException e) {
            AbortException abortException = new AbortException("Exception thrown while expanding the build version!");
            abortException.initCause(e);
            throw abortException;
        }

        VirtualChannel virtualChannel = launcher.getChannel();
        if (virtualChannel == null) {
            throw new AbortException("Failed to acquire VirtualChannel from target node!");
        }

        virtualChannel.call(new DeployCallable(
                workspace,
                listener,
                expandedHostname,
                bmCredentialsId,
                bmCredentials,
                tfCredentialsId,
                tfCredentials,
                expandedBuildVersion,
                getBuildCause(build),
                build.getNumber(),
                createBuildInfoCartridge,
                activateBuild,
                sourcePaths,
                tempDirectory,
                getDescriptor().getHttpProxyHost(),
                getDescriptor().getHttpProxyPort(),
                getDescriptor().getHttpProxyUsername(),
                getDescriptor().getHttpProxyPassword(),
                getDescriptor().getDisableSSLValidation()
        ));

        logger.println();
        logger.println(String.format("--[E: %s]--", getDescriptor().getDisplayName()));
        logger.println();
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    @Extension
    @Symbol("osfBuilderSuiteForSFCCDeploy")
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        private String httpProxyHost;
        private String httpProxyPort;
        private String httpProxyUsername;
        private String httpProxyPassword;
        private Boolean disableSSLValidation;

        public DescriptorImpl() {
            load();
        }

        public String getDisplayName() {
            return "OSF Builder Suite For Salesforce Commerce Cloud :: Deploy";
        }

        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillBmCredentialsIdItems(@AncestorInPath Item context,
                                                       @QueryParameter String credentialsId) {

            if (context == null || !context.hasPermission(Item.CONFIGURE)) {
                return new ListBoxModel();
            }

            return new StandardListBoxModel().includeEmptyValue().includeMatchingAs(
                    context instanceof hudson.model.Queue.Task
                            ? Tasks.getAuthenticationOf((hudson.model.Queue.Task) context)
                            : ACL.SYSTEM,
                    context,
                    StandardCredentials.class,
                    URIRequirementBuilder.create().build(),
                    CredentialsMatchers.instanceOf(BusinessManagerAuthCredentials.class)
            );
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillTfCredentialsIdItems(@AncestorInPath Item context,
                                                       @QueryParameter String credentialsId) {

            if (context == null || !context.hasPermission(Item.CONFIGURE)) {
                return new ListBoxModel();
            }

            return new StandardListBoxModel().includeEmptyValue().includeMatchingAs(
                    context instanceof hudson.model.Queue.Task
                            ? Tasks.getAuthenticationOf((hudson.model.Queue.Task) context)
                            : ACL.SYSTEM,
                    context,
                    StandardCredentials.class,
                    URIRequirementBuilder.create().build(),
                    CredentialsMatchers.instanceOf(TwoFactorAuthCredentials.class)
            );
        }

        @SuppressWarnings("WeakerAccess")
        public String getHttpProxyHost() {
            return httpProxyHost;
        }

        @SuppressWarnings({"WeakerAccess", "unused"})
        public void setHttpProxyHost(String httpProxyHost) {
            this.httpProxyHost = httpProxyHost;
        }

        @SuppressWarnings("WeakerAccess")
        public String getHttpProxyPort() {
            return httpProxyPort;
        }

        @SuppressWarnings({"WeakerAccess", "unused"})
        public void setHttpProxyPort(String httpProxyPort) {
            this.httpProxyPort = httpProxyPort;
        }

        @SuppressWarnings("WeakerAccess")
        public String getHttpProxyUsername() {
            return httpProxyUsername;
        }

        @SuppressWarnings({"WeakerAccess", "unused"})
        public void setHttpProxyUsername(String httpProxyUsername) {
            this.httpProxyUsername = httpProxyUsername;
        }

        @SuppressWarnings("WeakerAccess")
        public String getHttpProxyPassword() {
            return httpProxyPassword;
        }

        @SuppressWarnings({"WeakerAccess", "unused"})
        public void setHttpProxyPassword(String httpProxyPassword) {
            this.httpProxyPassword = httpProxyPassword;
        }

        @SuppressWarnings("WeakerAccess")
        public Boolean getDisableSSLValidation() {
            return disableSSLValidation;
        }

        @SuppressWarnings({"WeakerAccess", "unused"})
        public void setDisableSSLValidation(Boolean disableSSLValidation) {
            this.disableSSLValidation = disableSSLValidation;
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            httpProxyHost = formData.getString("httpProxyHost");
            httpProxyPort = formData.getString("httpProxyPort");
            httpProxyUsername = formData.getString("httpProxyUsername");
            httpProxyPassword = formData.getString("httpProxyPassword");
            disableSSLValidation = formData.getBoolean("disableSSLValidation");

            save();

            return super.configure(req, formData);
        }
    }

    private static class DeployCallable extends MasterToSlaveCallable<Void, IOException> {

        private static final long serialVersionUID = 1L;

        private final FilePath workspace;
        private final TaskListener listener;
        private final String hostname;
        private final String bmCredentialsId;
        private final BusinessManagerAuthCredentials bmCredentials;
        private final String tfCredentialsId;
        private final TwoFactorAuthCredentials tfCredentials;
        private final String buildVersion;
        private final String buildCause;
        private final Integer buildNumber;
        private final Boolean createBuildInfoCartridge;
        private final Boolean activateBuild;
        private final List<SourcePath> sourcePaths;
        private final String tempDirectory;
        private final String httpProxyHost;
        private final String httpProxyPort;
        private final String httpProxyUsername;
        private final String httpProxyPassword;
        private final Boolean disableSSLValidation;

        @SuppressWarnings("WeakerAccess")
        public DeployCallable(
                FilePath workspace,
                TaskListener listener,
                String hostname,
                String bmCredentialsId,
                BusinessManagerAuthCredentials bmCredentials,
                String tfCredentialsId,
                TwoFactorAuthCredentials tfCredentials,
                String buildVersion,
                String buildCause,
                Integer buildNumber,
                Boolean createBuildInfoCartridge,
                Boolean activateBuild,
                List<SourcePath> sourcePaths,
                String tempDirectory,
                String httpProxyHost,
                String httpProxyPort,
                String httpProxyUsername,
                String httpProxyPassword,
                Boolean disableSSLValidation) {

            this.workspace = workspace;
            this.listener = listener;
            this.hostname = hostname;
            this.bmCredentialsId = bmCredentialsId;
            this.bmCredentials = bmCredentials;
            this.tfCredentialsId = tfCredentialsId;
            this.tfCredentials = tfCredentials;
            this.buildVersion = buildVersion;
            this.buildCause = buildCause;
            this.buildNumber = buildNumber;
            this.createBuildInfoCartridge = createBuildInfoCartridge;
            this.activateBuild = activateBuild;
            this.sourcePaths = sourcePaths;
            this.tempDirectory = tempDirectory;
            this.httpProxyHost = httpProxyHost;
            this.httpProxyPort = httpProxyPort;
            this.httpProxyUsername = httpProxyUsername;
            this.httpProxyPassword = httpProxyPassword;
            this.disableSSLValidation = disableSSLValidation;
        }

        @Override
        public Void call() throws IOException {
            PrintStream logger = listener.getLogger();

            if (StringUtils.isEmpty(hostname)) {
                logger.println();
                throw new AbortException(
                        "Missing value for \"Instance Hostname\"!" + " " +
                                "We can't make a build without a target where to deploy it, can't we?"
                );
            }

            if (StringUtils.isEmpty(bmCredentialsId)) {
                logger.println();
                throw new AbortException(
                        "Missing \"Business Manager Credentials\"!" + " " +
                                "We can't deploy the build without proper credentials, can't we?"
                );
            }

            if (bmCredentials == null) {
                logger.println();
                throw new AbortException(
                        "Failed to load \"Business Manager Credentials\"!" + " " +
                                "Something's wrong but not sure who's blame it is..."
                );
            }

            if (StringUtils.isNotEmpty(tfCredentialsId)) {
                if (tfCredentials == null) {
                    logger.println();
                    throw new AbortException(
                            "Failed to load \"Two Factor Auth Credentials\"!" + " " +
                                    "Something's wrong but not sure who's blame it is..."
                    );
                } else if (StringUtils.isEmpty(StringUtils.trim(tfCredentials.getServerCertificate()))) {
                    logger.println();
                    throw new AbortException(
                            "Failed to load \"Two Factor Auth Credentials\"!" + " " +
                                    "Missing value for \"Server Certificate\"!"
                    );
                } else if (StringUtils.isEmpty(StringUtils.trim(tfCredentials.getClientCertificate()))) {
                    logger.println();
                    throw new AbortException(
                            "Failed to load \"Two Factor Auth Credentials\"!" + " " +
                                    "Missing value for \"Client Certificate\"!"
                    );
                } else if (StringUtils.isEmpty(StringUtils.trim(tfCredentials.getClientPrivateKey()))) {
                    logger.println();
                    throw new AbortException(
                            "Failed to load \"Two Factor Auth Credentials\"!" + " " +
                                    "Missing value for \"Client Private Key\"!"
                    );
                }
            }

            if (StringUtils.isEmpty(buildVersion)) {
                logger.println();
                throw new AbortException(
                        "Missing \"Build Version\"!" + " " +
                                "We need a version name for the build we're about to do!"
                );
            }

            Pattern validationBuildVersionPattern = Pattern.compile("^[a-z0-9_.]+$", Pattern.CASE_INSENSITIVE);
            Matcher validationBuildVersionMatcher = validationBuildVersionPattern.matcher(buildVersion);

            if (!validationBuildVersionMatcher.matches()) {
                logger.println();
                throw new AbortException(
                        String.format("Invalid value \"%s\" for build version!", buildVersion) + " " +
                                "Only alphanumeric, \"_\" and \".\" characters are allowed."
                );
            }

            if (sourcePaths == null || sourcePaths.isEmpty()) {
                logger.println();
                throw new AbortException(
                        "No \"Sources\" defined!" + " " +
                                "We don't want to have an empty build, do we?"
                );
            }

            if (StringUtils.isEmpty(tempDirectory)) {
                logger.println();
                throw new AbortException(
                        "Missing \"Temp Directory\"!" + " " +
                                "We need a temporary place to store the build before we can deploy it!"
                );
            }

            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMdd", Locale.ENGLISH);
            simpleDateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));

            String codeVersionYearMonthDay = simpleDateFormat.format(Calendar.getInstance().getTime());
            String codeVersionString = String.format("b%s_%s_%s", buildNumber, codeVersionYearMonthDay, buildVersion);

            File wDirectory = new File(workspace.getRemote());
            File tDirectory = new File(wDirectory, tempDirectory);

            Path wDirectoryPath = wDirectory.toPath().normalize();
            Path tDirectoryPath = tDirectory.toPath().normalize();

            if (!tDirectoryPath.startsWith(wDirectoryPath)) {
                logger.println();
                throw new AbortException(
                        "Invalid value for \"Temp Directory\"! The path needs to be inside the workspace!"
                );
            }


            /* Setting up temporary build directory */
            logger.println("[+] Setting up temporary build directory");

            if (!tDirectory.exists()) {
                if (!tDirectory.mkdirs()) {
                    logger.println();
                    throw new AbortException(String.format("Failed to create %s!", tDirectory.getAbsolutePath()));
                }
            }

            File[] tDirectoryFiles = tDirectory.listFiles();
            if (tDirectoryFiles != null) {
                for (File tDirectoryFile : tDirectoryFiles) {
                    if (tDirectoryFile.isDirectory()) {
                        try {
                            FileUtils.deleteDirectory(tDirectoryFile);
                        } catch (IOException e) {
                            logger.println();
                            AbortException abortException = new AbortException(String.format(
                                    "Exception thrown while deleting \"%s\"!\n%s",
                                    tDirectoryFile.getAbsolutePath(),
                                    ExceptionUtils.getStackTrace(e)
                            ));
                            abortException.initCause(e);
                            throw abortException;
                        }
                    } else {
                        if (!tDirectoryFile.delete()) {
                            logger.println();
                            throw new AbortException(String.format(
                                    "Failed to delete \"%s\"!", tDirectoryFile.getAbsolutePath()
                            ));
                        }
                    }
                }
            }

            logger.println(" + Ok");
            /* Setting up temporary build directory */


            /* Creating ZIP archives of the cartridges */
            logger.println();
            logger.println("[+] Creating ZIP archives of the cartridges");

            List<File> zippedCartridges = new ArrayList<>();

            for (SourcePath sourcePath : sourcePaths) {
                Path pSourcePath = Paths.get(wDirectory.getAbsolutePath(), sourcePath.getSourcePath()).normalize();
                File fSourcePath = pSourcePath.toFile();

                if (!pSourcePath.startsWith(wDirectoryPath)) {
                    logger.println();
                    throw new AbortException(
                            "Invalid value for \"Source Paths\"! The path needs to be inside the workspace!"
                    );
                }

                if (!fSourcePath.exists()) {
                    logger.println();
                    throw new AbortException(
                            "Invalid value for \"Source Paths\"!" + " " +
                                    String.format("\"%s\" does not exist!", sourcePath.getSourcePath())
                    );
                }

                List<ExcludePattern> sourcePatterns = sourcePath.getExcludePatterns();
                List<MatchPattern> excludePatterns = new ArrayList<>();

                if (sourcePatterns != null) {
                    excludePatterns.addAll(sourcePatterns.stream()
                            .map(ExcludePattern::getExcludePattern)
                            .filter(StringUtils::isNotEmpty)
                            .map((p) -> MatchPattern.fromString("%ant[" + File.separator + p + "]"))
                            .collect(Collectors.toList())
                    );
                }

                File[] cartridges = fSourcePath.listFiles(File::isDirectory);
                if (cartridges != null) {
                    for (File cartridge : cartridges) {
                        File cartridgeZip = new File(tDirectory, String.format("%s.zip", cartridge.getName()));
                        if (cartridgeZip.exists()) {
                            logger.println();
                            throw new AbortException(
                                    "Failed to ZIP cartridge!" + " " +
                                            String.format("\"%s\" already exists!", cartridge.getName())
                            );
                        }

                        Boolean excludeCartridge = excludePatterns.stream().anyMatch((pattern) -> {
                            String pathToMatch = File.separator + cartridge.getName() + File.separator;
                            return pattern.matchPath(pathToMatch, true);
                        });

                        if (excludeCartridge) {
                            continue;
                        }

                        File[] cartridgeFiles = cartridge.listFiles();
                        if (cartridgeFiles == null || cartridgeFiles.length < 1) {
                            continue;
                        }

                        logger.println(String.format(" - %s", cartridge.getName()));

                        ZipUtil.pack(cartridge, cartridgeZip, (path) -> {
                            Boolean excludeFile = excludePatterns.stream().anyMatch((pattern) -> {
                                String pathToMatch = File.separator + cartridge.getName() + File.separator + path;
                                return pattern.matchPath(pathToMatch, true);
                            });

                            if (excludeFile) {
                                return null;
                            }

                            return cartridge.getName() + "/" + path;
                        });

                        zippedCartridges.add(cartridgeZip);
                    }
                }
            }

            if (createBuildInfoCartridge != null && createBuildInfoCartridge) {
                File cartridgeZip = new File(tDirectory, "inf_build.zip");
                if (cartridgeZip.exists()) {
                    logger.println();
                    throw new AbortException("Failed to ZIP cartridge! \"inf_build\" already exists!");
                }

                logger.println(" - inf_build");

                SimpleDateFormat simpleDateFormatProperties = new SimpleDateFormat(
                        "EEE MMM dd HH:mm:ss z yyyy", Locale.ENGLISH
                );
                simpleDateFormatProperties.setTimeZone(TimeZone.getTimeZone("GMT"));

                SimpleDateFormat simpleDateFormatResource = new SimpleDateFormat(
                        "EEEE, dd MMMM yyyy HH:mm:ss z", Locale.ENGLISH
                );
                simpleDateFormatResource.setTimeZone(TimeZone.getTimeZone("GMT"));

                Date currentDate = new Date();
                String strDateFormatProperties = simpleDateFormatProperties.format(currentDate);
                String strDateFormatResource = simpleDateFormatResource.format(currentDate);

                @SuppressWarnings("StringBufferReplaceableByString")
                StringBuilder strProject = new StringBuilder();
                strProject.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
                strProject.append("<projectDescription>\n");
                strProject.append("    <name>inf_build</name>\n");
                strProject.append("    <comment></comment>\n");
                strProject.append("    <projects></projects>\n");
                strProject.append("    <buildSpec>\n");
                strProject.append("        <buildCommand>\n");
                strProject.append("            <name>com.demandware.studio.core.beehiveElementBuilder</name>\n");
                strProject.append("            <arguments></arguments>\n");
                strProject.append("        </buildCommand>\n");
                strProject.append("    </buildSpec>\n");
                strProject.append("    <natures>\n");
                strProject.append("        <nature>com.demandware.studio.core.beehiveNature</nature>\n");
                strProject.append("    </natures>\n");
                strProject.append("</projectDescription>\n");

                @SuppressWarnings("StringBufferReplaceableByString")
                StringBuilder strProperties = new StringBuilder();
                strProperties.append("## cartridge.properties for cartridge inf_build\n");
                strProperties.append(String.format("#%s\n", strDateFormatProperties));
                strProperties.append("demandware.cartridges.inf_build.id=inf_build\n");
                strProperties.append("demandware.cartridges.inf_build.multipleLanguageStorefront=true\n");

                @SuppressWarnings("StringBufferReplaceableByString")
                StringBuilder strTemplate = new StringBuilder();
                strTemplate.append(String.format(
                        "<isif condition=\"${dw.system.System.getInstanceType() != %s}\">\n",
                        "dw.system.System.PRODUCTION_SYSTEM"
                ));
                strTemplate.append(String.format(
                        "    <!--( org.jenkinsci.plugins.osfbuildersuiteforsfcc.deploy:" +
                                "24fe7377-078d-4022-8d98-e2ef2ac25a5e = %s )-->\n",
                        strDateFormatResource
                ));
                strTemplate.append(String.format(
                        "    <!--( org.jenkinsci.plugins.osfbuildersuiteforsfcc.deploy:" +
                                "3b20a229-0e1c-4da7-b7d5-55d26cfe3aeb = %s )-->\n",
                        buildNumber
                ));
                strTemplate.append(String.format(
                        "    <!--( org.jenkinsci.plugins.osfbuildersuiteforsfcc.deploy:" +
                                "04a6ea95-e220-4256-8c16-70c8f398eac7 = %s )-->\n",
                        codeVersionString
                ));
                strTemplate.append(String.format(
                        "    <!--( org.jenkinsci.plugins.osfbuildersuiteforsfcc.deploy:" +
                                "1b753575-7d16-4964-b17f-16250e5c902f = %s )-->\n",
                        StringEscapeUtils.escapeHtml4(buildCause)
                ));
                strTemplate.append("</isif>\n");

                @SuppressWarnings("StringBufferReplaceableByString")
                StringBuilder strResource = new StringBuilder();
                strResource.append("########################################################\n");
                strResource.append("# Build date, number, version and cause\n");
                strResource.append("########################################################\n");
                strResource.append(String.format("build.date=%s\n", strDateFormatResource));
                strResource.append(String.format("build.number=%s\n", buildNumber));
                strResource.append(String.format("build.version=%s\n", codeVersionString));
                strResource.append(String.format("build.cause=%s\n", buildCause));

                ZipEntrySource[] zipEntrySources = new ZipEntrySource[] {
                        new ByteSource(
                                "inf_build/.project",
                                strProject.toString().getBytes(Charset.forName("UTF-8"))
                        ),
                        new ByteSource(
                                "inf_build/cartridge/inf_build.properties",
                                strProperties.toString().getBytes(Charset.forName("UTF-8"))
                        ),
                        new ByteSource(
                                "inf_build/cartridge/templates/default/build.isml",
                                strTemplate.toString().getBytes(Charset.forName("UTF-8"))
                        ),
                        new ByteSource(
                                "inf_build/cartridge/templates/resources/build.properties",
                                strResource.toString().getBytes(Charset.forName("UTF-8"))
                        )
                };

                ZipUtil.pack(zipEntrySources, cartridgeZip);
                zippedCartridges.add(cartridgeZip);
            }

            logger.println(" + Ok");
            /* Creating ZIP archives of the cartridges */


            /* Setup HTTP Client */
            HttpClientBuilder httpClientBuilder = HttpClients.custom();
            httpClientBuilder.setUserAgent("Jenkins (OSF Builder Suite For Salesforce Commerce Cloud)");
            httpClientBuilder.setDefaultCookieStore(new BasicCookieStore());

            httpClientBuilder.addInterceptorFirst((HttpRequestInterceptor) (request, context) -> {
                if (!request.containsHeader("Accept-Encoding")) {
                    request.addHeader("Accept-Encoding", "gzip");
                }
            });

            httpClientBuilder.addInterceptorFirst((HttpResponseInterceptor) (response, context) -> {
                HttpEntity entity = response.getEntity();
                if (entity != null) {
                    Header header = entity.getContentEncoding();
                    if (header != null) {
                        for (HeaderElement headerElement : header.getElements()) {
                            if (headerElement.getName().equalsIgnoreCase("gzip")) {
                                response.setEntity(new GzipDecompressingEntity(response.getEntity()));
                                return;
                            }
                        }
                    }
                }
            });

            httpClientBuilder.setDefaultConnectionConfig(ConnectionConfig.custom()
                    .setBufferSize(5242880 /* 5 MegaBytes */)
                    .setFragmentSizeHint(5242880 /* 5 MegaBytes */)
                    .build()
            );

            httpClientBuilder.setDefaultRequestConfig(RequestConfig.custom()
                    .setSocketTimeout(300000 /* 5 minutes */)
                    .setConnectTimeout(300000 /* 5 minutes */)
                    .setConnectionRequestTimeout(300000 /* 5 minutes */)
                    .build()
            );

            org.apache.http.client.CredentialsProvider httpCredentialsProvider = new BasicCredentialsProvider();

            // Proxy Auth
            if (StringUtils.isNotEmpty(httpProxyHost) && StringUtils.isNotEmpty(httpProxyPort)) {
                Integer httpProxyPortInteger;

                try {
                    httpProxyPortInteger = Integer.valueOf(httpProxyPort);
                } catch (NumberFormatException e) {
                    logger.println();
                    throw new AbortException(
                            String.format("Invalid value \"%s\" for HTTP proxy port!", httpProxyPort) + " " +
                                    "Please enter a valid port number."
                    );
                }

                if (httpProxyPortInteger <= 0 || httpProxyPortInteger > 65535) {
                    logger.println();
                    throw new AbortException(
                            String.format("Invalid value \"%s\" for HTTP proxy port!", httpProxyPort) + " " +
                                    "Please enter a valid port number."
                    );
                }

                HttpHost httpClientProxy = new HttpHost(httpProxyHost, httpProxyPortInteger);
                httpClientBuilder.setProxy(httpClientProxy);

                if (StringUtils.isNotEmpty(httpProxyUsername) && StringUtils.isNotEmpty(httpProxyPassword)) {
                    if (httpProxyUsername.contains("\\")) {
                        String domain = httpProxyUsername.substring(0, httpProxyUsername.indexOf("\\"));
                        String user = httpProxyUsername.substring(httpProxyUsername.indexOf("\\") + 1);

                        httpCredentialsProvider.setCredentials(
                                new AuthScope(httpProxyHost, httpProxyPortInteger),
                                new NTCredentials(user, httpProxyPassword, "", domain)
                        );
                    } else {
                        httpCredentialsProvider.setCredentials(
                                new AuthScope(httpProxyHost, httpProxyPortInteger),
                                new UsernamePasswordCredentials(httpProxyUsername, httpProxyPassword)
                        );
                    }
                }
            }

            // WebDAV Auth
            String bmCredentialsUsername = bmCredentials.getUsername();
            String bmCredentialsPassword = bmCredentials.getPassword().getPlainText();
            httpCredentialsProvider.setCredentials(
                    new AuthScope(hostname, 443),
                    new UsernamePasswordCredentials(bmCredentialsUsername, bmCredentialsPassword)
            );

            httpClientBuilder.setDefaultCredentialsProvider(httpCredentialsProvider);

            SSLContextBuilder sslContextBuilder = SSLContexts.custom();

            if (tfCredentials != null) {
                Provider bouncyCastleProvider = new BouncyCastleProvider();

                // Server Certificate
                Reader serverCertificateReader = new StringReader(tfCredentials.getServerCertificate());
                PEMParser serverCertificateParser = new PEMParser(serverCertificateReader);

                JcaX509CertificateConverter serverCertificateConverter = new JcaX509CertificateConverter();
                serverCertificateConverter.setProvider(bouncyCastleProvider);

                X509Certificate serverCertificate;

                try {
                    serverCertificate = serverCertificateConverter.getCertificate(
                            (X509CertificateHolder) serverCertificateParser.readObject()
                    );
                } catch (CertificateException | IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while loading two factor auth server certificate!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    serverCertificate.checkValidity();
                } catch (CertificateExpiredException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "The server certificate used for two factor auth is expired!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                } catch (CertificateNotYetValidException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "The server certificate used for two factor auth is not yet valid!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                // Client Certificate
                Reader clientCertificateReader = new StringReader(tfCredentials.getClientCertificate());
                PEMParser clientCertificateParser = new PEMParser(clientCertificateReader);

                JcaX509CertificateConverter clientCertificateConverter = new JcaX509CertificateConverter();
                clientCertificateConverter.setProvider(bouncyCastleProvider);

                X509Certificate clientCertificate;

                try {
                    clientCertificate = clientCertificateConverter.getCertificate(
                            (X509CertificateHolder) clientCertificateParser.readObject()
                    );
                } catch (CertificateException | IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while loading two factor auth client certificate!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    clientCertificate.checkValidity();
                } catch (CertificateExpiredException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "The client certificate used for two factor auth is expired!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                } catch (CertificateNotYetValidException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "The client certificate used for two factor auth is not yet valid!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                // Client Private Key
                Reader clientPrivateKeyReader = new StringReader(tfCredentials.getClientPrivateKey());
                PEMParser clientPrivateKeyParser = new PEMParser(clientPrivateKeyReader);

                Object clientPrivateKeyObject;

                try {
                    clientPrivateKeyObject = clientPrivateKeyParser.readObject();
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while loading two factor auth client private key!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                PrivateKeyInfo clientPrivateKeyInfo;

                if (clientPrivateKeyObject instanceof PrivateKeyInfo) {
                    clientPrivateKeyInfo = (PrivateKeyInfo) clientPrivateKeyObject;
                } else if (clientPrivateKeyObject instanceof PEMKeyPair) {
                    clientPrivateKeyInfo = ((PEMKeyPair) clientPrivateKeyObject).getPrivateKeyInfo();
                } else {
                    logger.println();
                    throw new AbortException("Failed to load two factor auth client private key!");
                }

                // Trust Store
                KeyStore customTrustStore;

                try {
                    customTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());
                } catch (KeyStoreException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom trust store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    customTrustStore.load(null, null);
                } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom trust store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    customTrustStore.setCertificateEntry(hostname, serverCertificate);
                } catch (KeyStoreException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom trust store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    sslContextBuilder.loadTrustMaterial(customTrustStore, null);
                } catch (NoSuchAlgorithmException | KeyStoreException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom trust store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                // Key Store
                KeyFactory customKeyStoreKeyFactory;

                try {
                    customKeyStoreKeyFactory = KeyFactory.getInstance("RSA");
                } catch (NoSuchAlgorithmException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom key store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                PrivateKey customKeyStorePrivateKey;

                try {
                    customKeyStorePrivateKey = customKeyStoreKeyFactory.generatePrivate(
                            new PKCS8EncodedKeySpec(clientPrivateKeyInfo.getEncoded())
                    );
                } catch (InvalidKeySpecException | IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom key store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                KeyStore customKeyStore;

                try {
                    customKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                } catch (KeyStoreException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom key store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    customKeyStore.load(null, null);
                } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom key store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                char[] keyStorePassword = RandomStringUtils.randomAscii(32).toCharArray();

                try {
                    customKeyStore.setKeyEntry(
                            hostname, customKeyStorePrivateKey, keyStorePassword,
                            new X509Certificate[]{clientCertificate, serverCertificate}
                    );
                } catch (KeyStoreException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom key store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    sslContextBuilder.loadKeyMaterial(customKeyStore, keyStorePassword);
                } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom key store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }
            }

            if (disableSSLValidation != null && disableSSLValidation) {
                try {
                    sslContextBuilder.loadTrustMaterial(null, (TrustStrategy) (arg0, arg1) -> true);
                } catch (NoSuchAlgorithmException | KeyStoreException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while setting up the custom key store!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }
            }

            SSLContext customSSLContext;

            try {
                customSSLContext = sslContextBuilder.build();
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                logger.println();
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while creating custom SSL context!\n%s",
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }

            if (disableSSLValidation != null && disableSSLValidation) {
                httpClientBuilder.setSSLSocketFactory(
                        new SSLConnectionSocketFactory(
                                customSSLContext, NoopHostnameVerifier.INSTANCE
                        )
                );
            } else {
                httpClientBuilder.setSSLSocketFactory(
                        new SSLConnectionSocketFactory(
                                customSSLContext, SSLConnectionSocketFactory.getDefaultHostnameVerifier()
                        )
                );
            }

            CloseableHttpClient httpClient = httpClientBuilder.build();
            /* Setup HTTP Client */


            /* Checking if the new code version does not already exist on the server */
            logger.println();
            logger.println("[+] Checking if the new code version does not already exist on the server");
            logger.println(String.format(" - %s (%s)", hostname, codeVersionString));

            RequestBuilder chRequestBuilder = RequestBuilder.create("HEAD");
            chRequestBuilder.setUri(String.format(
                    "https://%s/on/demandware.servlet/webdav/Sites/Cartridges/%s",
                    hostname, codeVersionString
            ));

            CloseableHttpResponse chHttpResponse;

            try {
                chHttpResponse = httpClient.execute(chRequestBuilder.build());
            } catch (IOException e) {
                logger.println();
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while making HTTP request!\n%s",
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }

            try {
                chHttpResponse.close();
            } catch (IOException e) {
                logger.println();
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while making HTTP request!\n%s",
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }

            StatusLine chHttpStatusLine = chHttpResponse.getStatusLine();

            if (chHttpStatusLine.getStatusCode() != HttpStatus.SC_NOT_FOUND) {
                if (chHttpStatusLine.getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                    logger.println();
                    throw new AbortException("Invalid username or password!");
                } else if (chHttpStatusLine.getStatusCode() == HttpStatus.SC_OK) {
                    logger.println();
                    throw new AbortException("Code version already exists on the server!");
                } else {
                    logger.println();
                    throw new AbortException(String.format(
                            "%s - %s!", chHttpStatusLine.getStatusCode(), chHttpStatusLine.getReasonPhrase()
                    ));
                }
            }

            logger.println(" + Ok");
            /* Checking if the new code version does not already exist on the server */


            /* Creating new code version */
            logger.println();
            logger.println("[+] Creating new code version");
            logger.println(String.format(" - %s (%s)", hostname, codeVersionString));

            RequestBuilder crRequestBuilder = RequestBuilder.create("MKCOL");
            crRequestBuilder.setUri(String.format(
                    "https://%s/on/demandware.servlet/webdav/Sites/Cartridges/%s",
                    hostname, codeVersionString
            ));

            CloseableHttpResponse crHttpResponse;

            try {
                crHttpResponse = httpClient.execute(crRequestBuilder.build());
            } catch (IOException e) {
                logger.println();
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while making HTTP request!\n%s",
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }

            try {
                crHttpResponse.close();
            } catch (IOException e) {
                logger.println();
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while making HTTP request!\n%s",
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }

            StatusLine crHttpStatusLine = crHttpResponse.getStatusLine();

            if (crHttpStatusLine.getStatusCode() != HttpStatus.SC_CREATED) {
                if (crHttpStatusLine.getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                    logger.println();
                    throw new AbortException("Invalid username or password!");
                } else {
                    logger.println();
                    throw new AbortException(String.format(
                            "%s - %s!", crHttpStatusLine.getStatusCode(), crHttpStatusLine.getReasonPhrase()
                    ));
                }
            }

            logger.println(" + Ok");
            /* Creating new code version */


            /* Uploading cartridges */
            logger.println();
            logger.println("[+] Uploading cartridges");

            for (File zippedCartridge : zippedCartridges) {
                String zippedCartridgeName = zippedCartridge.getName();
                logger.println(String.format(" - %s", zippedCartridgeName));

                if (!zippedCartridge.exists()) {
                    logger.println();
                    throw new AbortException(String.format("\"%s\" does not exist!", zippedCartridgeName));
                }

                RequestBuilder upRequestBuilder = RequestBuilder.create("PUT");
                upRequestBuilder.setEntity(new FileEntity(zippedCartridge, ContentType.APPLICATION_OCTET_STREAM));
                upRequestBuilder.setUri(String.format(
                        "https://%s/on/demandware.servlet/webdav/Sites/Cartridges/%s/%s",
                        hostname, codeVersionString, zippedCartridgeName
                ));

                CloseableHttpResponse upHttpResponse;

                try {
                    upHttpResponse = httpClient.execute(upRequestBuilder.build());
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    upHttpResponse.close();
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                StatusLine upHttpStatusLine = upHttpResponse.getStatusLine();

                if (upHttpStatusLine.getStatusCode() != HttpStatus.SC_CREATED) {
                    if (upHttpStatusLine.getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                        logger.println();
                        throw new AbortException("Invalid username or password!");
                    } else {
                        logger.println();
                        throw new AbortException(String.format(
                                "%s - %s!", upHttpStatusLine.getStatusCode(), upHttpStatusLine.getReasonPhrase()
                        ));
                    }
                }

                List<NameValuePair> exHttpPostParams = new ArrayList<>();
                exHttpPostParams.add(new BasicNameValuePair("method", "UNZIP"));

                RequestBuilder exRequestBuilder = RequestBuilder.create("POST");
                exRequestBuilder.setEntity(new UrlEncodedFormEntity(exHttpPostParams, Consts.UTF_8));
                exRequestBuilder.setUri(String.format(
                        "https://%s/on/demandware.servlet/webdav/Sites/Cartridges/%s/%s",
                        hostname, codeVersionString, zippedCartridgeName
                ));

                CloseableHttpResponse exHttpResponse;

                try {
                    exHttpResponse = httpClient.execute(exRequestBuilder.build());
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    exHttpResponse.close();
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                StatusLine exHttpStatusLine = exHttpResponse.getStatusLine();

                if (exHttpStatusLine.getStatusCode() != HttpStatus.SC_CREATED) {
                    if (exHttpStatusLine.getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                        logger.println();
                        throw new AbortException("Invalid username or password!");
                    } else {
                        logger.println();
                        throw new AbortException(String.format(
                                "%s - %s!", exHttpStatusLine.getStatusCode(), exHttpStatusLine.getReasonPhrase()
                        ));
                    }
                }

                RequestBuilder rmRequestBuilder = RequestBuilder.create("DELETE");
                rmRequestBuilder.setUri(String.format(
                        "https://%s/on/demandware.servlet/webdav/Sites/Cartridges/%s/%s",
                        hostname, codeVersionString, zippedCartridgeName
                ));

                CloseableHttpResponse rmHttpResponse;

                try {
                    rmHttpResponse = httpClient.execute(rmRequestBuilder.build());
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                try {
                    rmHttpResponse.close();
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                StatusLine rmHttpStatusLine = rmHttpResponse.getStatusLine();

                if (rmHttpStatusLine.getStatusCode() != HttpStatus.SC_NO_CONTENT) {
                    if (rmHttpStatusLine.getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                        logger.println();
                        throw new AbortException("Invalid username or password!");
                    } else {
                        logger.println();
                        throw new AbortException(String.format(
                                "%s - %s!", rmHttpStatusLine.getStatusCode(), rmHttpStatusLine.getReasonPhrase()
                        ));
                    }
                }
            }

            logger.println(" + Ok");
            /* Uploading cartridges */


            /* Activating code version */
            if (activateBuild != null && activateBuild) {
                logger.println();
                logger.println("[+] Activating code version");
                logger.println(String.format(" - %s (%s)", hostname, codeVersionString));

                List<NameValuePair> lgHttpPostParams = new ArrayList<>();
                lgHttpPostParams.add(new BasicNameValuePair("LoginForm_Login", bmCredentialsUsername));
                lgHttpPostParams.add(new BasicNameValuePair("LoginForm_Password", bmCredentialsPassword));
                lgHttpPostParams.add(new BasicNameValuePair("LoginForm_RegistrationDomain", "Sites"));

                RequestBuilder lgRequestBuilder = RequestBuilder.create("POST");
                lgRequestBuilder.setEntity(new UrlEncodedFormEntity(lgHttpPostParams, Consts.UTF_8));
                lgRequestBuilder.setUri(String.format(
                        "https://%s/on/demandware.store/Sites-Site/default/ViewApplication-ProcessLogin",
                        hostname
                ));

                CloseableHttpResponse lgHttpResponse;

                try {
                    lgHttpResponse = httpClient.execute(lgRequestBuilder.build());
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                EntityUtils.consumeQuietly(lgHttpResponse.getEntity());

                try {
                    lgHttpResponse.close();
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                StatusLine lgHttpStatusLine = lgHttpResponse.getStatusLine();
                Header lgLocationHeader = lgHttpResponse.getLastHeader("Location");

                if (lgHttpStatusLine.getStatusCode() == HttpStatus.SC_MOVED_TEMPORARILY && lgLocationHeader != null) {
                    RequestBuilder lrRequestBuilder = RequestBuilder.create("GET");
                    lrRequestBuilder.setUri(lgLocationHeader.getValue());

                    CloseableHttpResponse lrHttpResponse;

                    try {
                        lrHttpResponse = httpClient.execute(lrRequestBuilder.build());
                    } catch (IOException e) {
                        logger.println();
                        AbortException abortException = new AbortException(String.format(
                                "Exception thrown while making HTTP request!\n%s",
                                ExceptionUtils.getStackTrace(e)
                        ));
                        abortException.initCause(e);
                        throw abortException;
                    }

                    EntityUtils.consumeQuietly(lrHttpResponse.getEntity());

                    try {
                        lrHttpResponse.close();
                    } catch (IOException e) {
                        logger.println();
                        AbortException abortException = new AbortException(String.format(
                                "Exception thrown while making HTTP request!\n%s",
                                ExceptionUtils.getStackTrace(e)
                        ));
                        abortException.initCause(e);
                        throw abortException;
                    }
                }

                RequestBuilder acRequestBuilder = RequestBuilder.create("GET");
                acRequestBuilder.setUri(String.format(
                        "https://%s/on/demandware.store/Sites-Site/default/ViewCodeDeployment-Activate"
                                + "?CodeVersionID=%s", hostname, codeVersionString
                ));

                CloseableHttpResponse acHttpResponse;

                try {
                    acHttpResponse = httpClient.execute(acRequestBuilder.build());
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                HttpEntity acHttpEntity = acHttpResponse.getEntity();
                StatusLine acHttpStatusLine = acHttpResponse.getStatusLine();

                if (acHttpEntity == null) {
                    logger.println();
                    throw new AbortException(String.format(
                            "Failed to activate code version! %s - %s!",
                            acHttpStatusLine.getStatusCode(),
                            acHttpStatusLine.getReasonPhrase()
                    ));
                }

                String acHttpEntityString;

                try {
                    acHttpEntityString = EntityUtils.toString(acHttpEntity, "UTF-8");
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                if (acHttpStatusLine.getStatusCode() != HttpStatus.SC_OK) {
                    logger.println();
                    throw new AbortException(String.format(
                            "Failed to activate code version! %s - %s!",
                            acHttpStatusLine.getStatusCode(),
                            acHttpStatusLine.getReasonPhrase()
                    ));
                }

                try {
                    acHttpResponse.close();
                } catch (IOException e) {
                    logger.println();
                    AbortException abortException = new AbortException(String.format(
                            "Exception thrown while making HTTP request!\n%s",
                            ExceptionUtils.getStackTrace(e)
                    ));
                    abortException.initCause(e);
                    throw abortException;
                }

                String acSuccessMessage = String.format("Successfully activated version '%s'", codeVersionString);
                if (!acHttpEntityString.contains(acSuccessMessage)) {
                    logger.println();
                    throw new AbortException(String.format(
                            "Failed to activate code version! %s - %s! HttpEntity=%s",
                            acHttpStatusLine.getStatusCode(),
                            acHttpStatusLine.getReasonPhrase(),
                            acHttpEntityString
                    ));
                }

                logger.println(" + Ok");
            }
            /* Activating code version */


            /* Close HTTP Client */
            try {
                httpClient.close();
            } catch (IOException e) {
                logger.println();
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while closing HTTP client!\n%s",
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }
            /* Close HTTP Client */


            return null;
        }
    }
}

