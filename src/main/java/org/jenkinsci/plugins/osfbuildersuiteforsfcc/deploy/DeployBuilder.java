package org.jenkinsci.plugins.osfbuildersuiteforsfcc.deploy;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
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
import jenkins.MasterToSlaveFileCallable;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import net.sf.json.JSONObject;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.codehaus.plexus.util.MatchPattern;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.credentials.HTTPProxyCredentials;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.credentials.OpenCommerceAPICredentials;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.credentials.TwoFactorAuthCredentials;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.deploy.repeatable.ExcludePattern;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.deploy.repeatable.SourcePath;
import org.jenkinsci.plugins.tokenmacro.MacroEvaluationException;
import org.jenkinsci.plugins.tokenmacro.TokenMacro;
import org.kohsuke.stapler.*;
import org.zeroturnaround.zip.ByteSource;
import org.zeroturnaround.zip.ZipEntrySource;
import org.zeroturnaround.zip.ZipUtil;

import javax.annotation.Nonnull;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


@SuppressWarnings("unused")
public class DeployBuilder extends Builder implements SimpleBuildStep {

    private String hostname;
    private String tfCredentialsId;
    private String ocCredentialsId;
    private String ocVersion;
    private String buildVersion;
    private Boolean createBuildInfoCartridge;
    private Boolean activateBuild;
    private List<SourcePath> sourcePaths;
    private String tempDirectory;

    @DataBoundConstructor
    public DeployBuilder(
            String hostname,
            String tfCredentialsId,
            String ocCredentialsId,
            String ocVersion,
            String buildVersion,
            Boolean createBuildInfoCartridge,
            Boolean activateBuild,
            List<SourcePath> sourcePaths,
            String tempDirectory) {

        this.hostname = hostname;
        this.tfCredentialsId = tfCredentialsId;
        this.ocCredentialsId = ocCredentialsId;
        this.ocVersion = ocVersion;
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
    public String getTfCredentialsId() {
        return tfCredentialsId;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setTfCredentialsId(String tfCredentialsId) {
        this.tfCredentialsId = StringUtils.trim(tfCredentialsId);
    }

    @SuppressWarnings("unused")
    public String getOcCredentialsId() {
        return ocCredentialsId;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setOcCredentialsId(String ocCredentialsId) {
        this.ocCredentialsId = ocCredentialsId;
    }

    @SuppressWarnings("unused")
    public String getOcVersion() {
        return ocVersion;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setOcVersion(String ocVersion) {
        this.ocVersion = ocVersion;
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

        TwoFactorAuthCredentials tfCredentials = null;
        if (StringUtils.isNotEmpty(tfCredentialsId)) {
            tfCredentials = com.cloudbees.plugins.credentials.CredentialsProvider.findCredentialById(
                    tfCredentialsId,
                    TwoFactorAuthCredentials.class,
                    build,
                    URIRequirementBuilder.create().build()
            );
        }

        if (tfCredentials != null) {
            com.cloudbees.plugins.credentials.CredentialsProvider.track(build, tfCredentials);
        }

        OpenCommerceAPICredentials ocCredentials = null;
        if (StringUtils.isNotEmpty(ocCredentialsId)) {
            ocCredentials = com.cloudbees.plugins.credentials.CredentialsProvider.findCredentialById(
                    ocCredentialsId,
                    OpenCommerceAPICredentials.class,
                    build,
                    URIRequirementBuilder.create().build()
            );
        }

        if (ocCredentials != null) {
            com.cloudbees.plugins.credentials.CredentialsProvider.track(build, ocCredentials);
        }

        String expandedBuildVersion;
        try {
            expandedBuildVersion = TokenMacro.expandAll(build, workspace, listener, buildVersion);
        } catch (MacroEvaluationException e) {
            AbortException abortException = new AbortException("Exception thrown while expanding the build version!");
            abortException.initCause(e);
            throw abortException;
        }

        HTTPProxyCredentials httpProxyCredentials = null;
        if (StringUtils.isNotEmpty(getDescriptor().getHttpProxyCredentialsId())) {
            httpProxyCredentials = com.cloudbees.plugins.credentials.CredentialsProvider.findCredentialById(
                    getDescriptor().getHttpProxyCredentialsId(),
                    HTTPProxyCredentials.class,
                    build,
                    URIRequirementBuilder.create().build()
            );
        }

        workspace.act(new DeployCallable(
                listener,
                expandedHostname,
                tfCredentialsId,
                tfCredentials,
                ocCredentialsId,
                ocCredentials,
                ocVersion,
                expandedBuildVersion,
                getBuildCause(build),
                build.getNumber(),
                createBuildInfoCartridge,
                activateBuild,
                sourcePaths,
                tempDirectory,
                httpProxyCredentials,
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
        private String httpProxyCredentialsId;
        private Boolean disableSSLValidation;

        public DescriptorImpl() {
            load();
        }

        public String getDisplayName() {
            return "OSF Builder Suite For Salesforce Commerce Cloud :: Deploy";
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillTfCredentialsIdItems(
                @AncestorInPath Item item,
                @QueryParameter String credentialsId) {

            StandardListBoxModel result = new StandardListBoxModel();

            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return result.includeCurrentValue(credentialsId);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ)
                        && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return result.includeCurrentValue(credentialsId);
                }
            }

            return result
                    .includeEmptyValue()
                    .includeMatchingAs(
                            item instanceof hudson.model.Queue.Task
                                    ? Tasks.getAuthenticationOf((hudson.model.Queue.Task) item)
                                    : ACL.SYSTEM,
                            item,
                            StandardCredentials.class,
                            URIRequirementBuilder.create().build(),
                            CredentialsMatchers.instanceOf(TwoFactorAuthCredentials.class)
                    )
                    .includeCurrentValue(credentialsId);
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillOcCredentialsIdItems(
                @AncestorInPath Item item,
                @QueryParameter String credentialsId) {

            StandardListBoxModel result = new StandardListBoxModel();

            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return result.includeCurrentValue(credentialsId);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ)
                        && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return result.includeCurrentValue(credentialsId);
                }
            }

            return result
                    .includeEmptyValue()
                    .includeMatchingAs(
                            item instanceof hudson.model.Queue.Task
                                    ? Tasks.getAuthenticationOf((hudson.model.Queue.Task) item)
                                    : ACL.SYSTEM,
                            item,
                            StandardCredentials.class,
                            URIRequirementBuilder.create().build(),
                            CredentialsMatchers.instanceOf(OpenCommerceAPICredentials.class)
                    )
                    .includeCurrentValue(credentialsId);
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillHttpProxyCredentialsIdItems(
                @AncestorInPath Item item,
                @QueryParameter String credentialsId) {

            StandardListBoxModel result = new StandardListBoxModel();

            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return result.includeCurrentValue(credentialsId);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ)
                        && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return result.includeCurrentValue(credentialsId);
                }
            }

            return result
                    .includeEmptyValue()
                    .includeMatchingAs(
                            item instanceof hudson.model.Queue.Task
                                    ? Tasks.getAuthenticationOf((hudson.model.Queue.Task) item)
                                    : ACL.SYSTEM,
                            item,
                            StandardCredentials.class,
                            URIRequirementBuilder.create().build(),
                            CredentialsMatchers.instanceOf(HTTPProxyCredentials.class)
                    )
                    .includeCurrentValue(credentialsId);
        }

        @SuppressWarnings("WeakerAccess")
        public String getHttpProxyCredentialsId() {
            return httpProxyCredentialsId;
        }

        @SuppressWarnings({"unused"})
        public void setHttpProxyCredentialsId(String httpProxyCredentialsId) {
            this.httpProxyCredentialsId = httpProxyCredentialsId;
        }

        @SuppressWarnings("WeakerAccess")
        public Boolean getDisableSSLValidation() {
            return disableSSLValidation;
        }

        @SuppressWarnings({"unused"})
        public void setDisableSSLValidation(Boolean disableSSLValidation) {
            this.disableSSLValidation = disableSSLValidation;
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            httpProxyCredentialsId = formData.getString("httpProxyCredentialsId");
            disableSSLValidation = formData.getBoolean("disableSSLValidation");

            save();

            return super.configure(req, formData);
        }
    }

    private static class DeployCallable extends MasterToSlaveFileCallable<Void> {

        private static final long serialVersionUID = 1L;

        private final TaskListener listener;
        private final String hostname;
        private final String tfCredentialsId;
        private final TwoFactorAuthCredentials tfCredentials;
        private final String ocCredentialsId;
        private final OpenCommerceAPICredentials ocCredentials;
        private final String ocVersion;
        private final String buildVersion;
        private final String buildCause;
        private final Integer buildNumber;
        private final Boolean createBuildInfoCartridge;
        private final Boolean activateBuild;
        private final List<SourcePath> sourcePaths;
        private final String tempDirectory;
        private final HTTPProxyCredentials httpProxyCredentials;
        private final Boolean disableSSLValidation;

        @SuppressWarnings("WeakerAccess")
        public DeployCallable(
                TaskListener listener,
                String hostname,
                String tfCredentialsId,
                TwoFactorAuthCredentials tfCredentials,
                String ocCredentialsId,
                OpenCommerceAPICredentials ocCredentials,
                String ocVersion,
                String buildVersion,
                String buildCause,
                Integer buildNumber,
                Boolean createBuildInfoCartridge,
                Boolean activateBuild,
                List<SourcePath> sourcePaths,
                String tempDirectory,
                HTTPProxyCredentials httpProxyCredentials,
                Boolean disableSSLValidation) {

            this.listener = listener;
            this.hostname = hostname;
            this.tfCredentialsId = tfCredentialsId;
            this.tfCredentials = tfCredentials;
            this.ocCredentialsId = ocCredentialsId;
            this.ocCredentials = ocCredentials;
            this.ocVersion = ocVersion;
            this.buildVersion = buildVersion;
            this.buildCause = buildCause;
            this.buildNumber = buildNumber;
            this.createBuildInfoCartridge = createBuildInfoCartridge;
            this.activateBuild = activateBuild;
            this.sourcePaths = sourcePaths;
            this.tempDirectory = tempDirectory;
            this.httpProxyCredentials = httpProxyCredentials;
            this.disableSSLValidation = disableSSLValidation;
        }

        @Override
        public Void invoke(File dir, VirtualChannel channel) throws IOException {
            PrintStream logger = listener.getLogger();

            if (StringUtils.isEmpty(hostname)) {
                throw new AbortException(
                        "Missing value for \"Instance Hostname\"!" + " " +
                                "We can't make a build without a target where to deploy it, can't we?"
                );
            }

            if (StringUtils.isNotEmpty(tfCredentialsId)) {
                if (tfCredentials == null) {
                    throw new AbortException(
                            "Failed to load \"Two Factor Auth Credentials\"!" + " " +
                                    "Something's wrong but not sure who's blame it is..."
                    );
                } else if (StringUtils.isEmpty(StringUtils.trim(tfCredentials.getServerCertificate()))) {
                    throw new AbortException(
                            "Failed to load \"Two Factor Auth Credentials\"!" + " " +
                                    "Missing value for \"Server Certificate\"!"
                    );
                } else if (StringUtils.isEmpty(StringUtils.trim(tfCredentials.getClientCertificate()))) {
                    throw new AbortException(
                            "Failed to load \"Two Factor Auth Credentials\"!" + " " +
                                    "Missing value for \"Client Certificate\"!"
                    );
                } else if (StringUtils.isEmpty(StringUtils.trim(tfCredentials.getClientPrivateKey()))) {
                    throw new AbortException(
                            "Failed to load \"Two Factor Auth Credentials\"!" + " " +
                                    "Missing value for \"Client Private Key\"!"
                    );
                }
            }

            if (StringUtils.isEmpty(ocCredentialsId)) {
                throw new AbortException(
                        "Missing \"Open Commerce API Credentials\"!" + " " +
                                "We can't deploy the build without proper credentials, can't we?"
                );
            }

            if (ocCredentials == null) {
                throw new AbortException(
                        "Failed to load \"Open Commerce API Credentials\"!" + " " +
                                "Something's wrong but not sure who's blame it is..."
                );
            }

            if (StringUtils.isEmpty(ocVersion)) {
                throw new AbortException(
                        "Missing \"Open Commerce API Version\"!" + " " +
                                "We can't use Open Commerce API without specifying a version, can't we?"
                );
            }

            if (StringUtils.isEmpty(buildVersion)) {
                throw new AbortException(
                        "Missing \"Build Version\"!" + " " +
                                "We need a version name for the build we're about to do!"
                );
            }

            Pattern validationBuildVersionPattern = Pattern.compile("^[a-z0-9_.]+$", Pattern.CASE_INSENSITIVE);
            Matcher validationBuildVersionMatcher = validationBuildVersionPattern.matcher(buildVersion);

            if (!validationBuildVersionMatcher.matches()) {
                throw new AbortException(
                        String.format("Invalid value \"%s\" for build version!", buildVersion) + " " +
                                "Only alphanumeric, \"_\" and \".\" characters are allowed."
                );
            }

            if (sourcePaths == null || sourcePaths.isEmpty()) {
                throw new AbortException(
                        "No \"Sources\" defined!" + " " +
                                "We don't want to have an empty build, do we?"
                );
            }

            if (StringUtils.isEmpty(tempDirectory)) {
                throw new AbortException(
                        "Missing \"Temp Directory\"!" + " " +
                                "We need a temporary place to store the build before we can deploy it!"
                );
            }

            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMdd", Locale.ENGLISH);
            simpleDateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));

            String codeVersionYearMonthDay = simpleDateFormat.format(new Date().getTime());
            String codeVersionString = String.format("b%s_%s_%s", buildNumber, codeVersionYearMonthDay, buildVersion);

            @SuppressWarnings("UnnecessaryLocalVariable")
            File wDirectory = dir;
            File tDirectory = new File(wDirectory, tempDirectory);

            Path wDirectoryPath = wDirectory.toPath().normalize();
            Path tDirectoryPath = tDirectory.toPath().normalize();

            if (!tDirectoryPath.startsWith(wDirectoryPath)) {
                throw new AbortException(
                        "Invalid value for \"Temp Directory\"! The path needs to be inside the workspace!"
                );
            }


            /* Setting up temporary build directory */
            logger.println("[+] Setting up temporary build directory");

            if (!tDirectory.exists()) {
                if (!tDirectory.mkdirs()) {
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
                    throw new AbortException(
                            "Invalid value for \"Source Paths\"! The path needs to be inside the workspace!"
                    );
                }

                if (!fSourcePath.exists()) {
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
                            throw new AbortException(
                                    "Failed to ZIP cartridge!" + " " +
                                            String.format("\"%s\" already exists!", cartridge.getName())
                            );
                        }

                        boolean excludeCartridge = excludePatterns.stream().anyMatch((pattern) -> {
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
                            boolean excludeFile = excludePatterns.stream().anyMatch((pattern) -> {
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
                                strProject.toString().getBytes(StandardCharsets.UTF_8)
                        ),
                        new ByteSource(
                                "inf_build/cartridge/inf_build.properties",
                                strProperties.toString().getBytes(StandardCharsets.UTF_8)
                        ),
                        new ByteSource(
                                "inf_build/cartridge/templates/default/build.isml",
                                strTemplate.toString().getBytes(StandardCharsets.UTF_8)
                        ),
                        new ByteSource(
                                "inf_build/cartridge/templates/resources/build.properties",
                                strResource.toString().getBytes(StandardCharsets.UTF_8)
                        )
                };

                ZipUtil.pack(zipEntrySources, cartridgeZip);
                zippedCartridges.add(cartridgeZip);
            }

            logger.println(" + Ok");
            /* Creating ZIP archives of the cartridges */


            OpenCommerceAPI openCommerceAPI = new OpenCommerceAPI(
                    hostname,
                    httpProxyCredentials,
                    disableSSLValidation,
                    tfCredentials,
                    ocCredentials,
                    ocVersion,
                    codeVersionString
            );


            /* Creating new code version */
            logger.println();
            logger.println("[+] Creating new code version");
            logger.println(String.format(" - %s (%s)", hostname, codeVersionString));

            openCommerceAPI.createCodeVersion();

            logger.println(" + Ok");
            /* Creating new code version */


            /* Uploading cartridges */
            logger.println();
            logger.println("[+] Uploading cartridges");

            for (File zippedCartridge : zippedCartridges) {
                logger.println(String.format(" - %s", zippedCartridge.getName()));

                if (!zippedCartridge.exists()) {
                    throw new AbortException(String.format("\"%s\" does not exist!", zippedCartridge.getName()));
                }

                openCommerceAPI.uploadCartridgeZip(zippedCartridge);
                openCommerceAPI.unzipCartridge(zippedCartridge);
                openCommerceAPI.removeCartridgeZip(zippedCartridge);
            }

            logger.println(" + Ok");
            /* Uploading cartridges */


            /* Activating code version */
            if (activateBuild != null && activateBuild) {
                logger.println();
                logger.println("[+] Activating code version");
                logger.println(String.format(" - %s (%s)", hostname, codeVersionString));

                openCommerceAPI.activateCodeVersion();

                logger.println(" + Ok");
            }
            /* Activating code version */

            return null;
        }
    }
}

