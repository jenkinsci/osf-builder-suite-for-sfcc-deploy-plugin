package org.jenkinsci.plugins.osfbuildersuiteforsfcc.deploy.repeatable;

import hudson.Extension;
import hudson.model.Describable;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;
import java.util.List;

public class SourcePath implements Serializable, Describable<SourcePath> {

    private final String sourcePath;
    private final List<ExcludePattern> excludePatterns;

    @DataBoundConstructor
    public SourcePath(String sourcePath, List<ExcludePattern> excludePatterns) {
        this.sourcePath = sourcePath;
        this.excludePatterns = excludePatterns;
    }

    public String getSourcePath() {
        return sourcePath;
    }

    public List<ExcludePattern> getExcludePatterns() {
        return excludePatterns;
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) Jenkins.get().getDescriptor(getClass());
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SourcePath> {

        @Override
        public String getDisplayName() {
            return "OSF Builder Suite For Salesforce Commerce Cloud :: Deploy (SourcePath)";
        }
    }
}
