package org.jenkinsci.plugins.osfbuildersuiteforsfcc.deploy;

import hudson.AbortException;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.http.Consts;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.StatusLine;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.FileEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.credentials.BusinessManagerAuthCredentials;

import java.io.File;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

class WebDAV {
    static void checkBusinessManagerCredentials(
            CloseableHttpClient httpClient,
            String hostname,
            BusinessManagerAuthCredentials bmCredentials) throws IOException {

        RequestBuilder requestBuilder = RequestBuilder.create("HEAD");
        requestBuilder.setHeader("Authorization", String.format(
                "Basic %s",
                Base64.getEncoder().encodeToString(
                        String.format(
                                "%s:%s",
                                bmCredentials.getUsername(),
                                bmCredentials.getPassword().getPlainText()
                        ).getBytes(Consts.UTF_8)
                )
        ));

        requestBuilder.setUri(String.format("https://%s/on/demandware.servlet/webdav/Sites/Cartridges/", hostname));

        CloseableHttpResponse httpResponse;

        try {
            httpResponse = httpClient.execute(requestBuilder.build());
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "\nException thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        try {
            httpResponse.close();
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "\nException thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        StatusLine httpStatusLine = httpResponse.getStatusLine();

        if (httpStatusLine.getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
            throw new AbortException(
                    "\nInvalid username or password for Business Manager Credentials! " +
                            "Or maybe the password expired and needs to be updated?"
            );
        }
    }

    static void uploadCartridgeZip(
            Map<String, String> authResponseMap,
            CloseableHttpClient httpClient,
            String hostname,
            String codeVersionString,
            File zippedCartridge) throws IOException {

        RequestBuilder requestBuilder = RequestBuilder.create("PUT");
        requestBuilder.setHeader("Authorization", String.format(
                "%s %s",
                authResponseMap.get("token_type"),
                authResponseMap.get("access_token")
        ));

        requestBuilder.setEntity(new FileEntity(zippedCartridge, ContentType.APPLICATION_OCTET_STREAM));
        requestBuilder.setUri(String.format(
                "https://%s/on/demandware.servlet/webdav/Sites/Cartridges/%s/%s",
                hostname,
                URLEncoder.encode(codeVersionString, "UTF-8"),
                URLEncoder.encode(zippedCartridge.getName(), "UTF-8")
        ));

        CloseableHttpResponse httpResponse;

        try {
            httpResponse = httpClient.execute(requestBuilder.build());
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "\nException thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        try {
            httpResponse.close();
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "\nException thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        StatusLine httpStatusLine = httpResponse.getStatusLine();

        if (httpStatusLine.getStatusCode() != HttpStatus.SC_CREATED) {
            if (httpStatusLine.getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                throw new AbortException("\nInvalid username or password!");
            } else {
                throw new AbortException(String.format(
                        "\n%s - %s!", httpStatusLine.getStatusCode(), httpStatusLine.getReasonPhrase()
                ));
            }
        }
    }

    static void unzipCartridge(
            Map<String, String> authResponseMap,
            CloseableHttpClient httpClient,
            String hostname,
            String codeVersionString,
            File zippedCartridge) throws IOException {

        List<NameValuePair> httpPostParams = new ArrayList<>();
        httpPostParams.add(new BasicNameValuePair("method", "UNZIP"));

        RequestBuilder requestBuilder = RequestBuilder.create("POST");
        requestBuilder.setHeader("Authorization", String.format(
                "%s %s",
                authResponseMap.get("token_type"),
                authResponseMap.get("access_token")
        ));

        requestBuilder.setEntity(new UrlEncodedFormEntity(httpPostParams, Consts.UTF_8));
        requestBuilder.setUri(String.format(
                "https://%s/on/demandware.servlet/webdav/Sites/Cartridges/%s/%s",
                hostname,
                URLEncoder.encode(codeVersionString, "UTF-8"),
                URLEncoder.encode(zippedCartridge.getName(), "UTF-8")
        ));

        CloseableHttpResponse httpResponse;

        try {
            httpResponse = httpClient.execute(requestBuilder.build());
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "\nException thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        try {
            httpResponse.close();
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "\nException thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        StatusLine httpStatusLine = httpResponse.getStatusLine();

        if (httpStatusLine.getStatusCode() != HttpStatus.SC_CREATED) {
            if (httpStatusLine.getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                throw new AbortException("\nInvalid username or password!");
            } else {
                throw new AbortException(String.format(
                        "\n%s - %s!", httpStatusLine.getStatusCode(), httpStatusLine.getReasonPhrase()
                ));
            }
        }
    }

    static void removeCartridgeZip(
            Map<String, String> authResponseMap,
            CloseableHttpClient httpClient,
            String hostname,
            String codeVersionString,
            File zippedCartridge) throws IOException {

        RequestBuilder requestBuilder = RequestBuilder.create("DELETE");
        requestBuilder.setHeader("Authorization", String.format(
                "%s %s",
                authResponseMap.get("token_type"),
                authResponseMap.get("access_token")
        ));

        requestBuilder.setUri(String.format(
                "https://%s/on/demandware.servlet/webdav/Sites/Cartridges/%s/%s",
                hostname,
                URLEncoder.encode(codeVersionString, "UTF-8"),
                URLEncoder.encode(zippedCartridge.getName(), "UTF-8")
        ));

        CloseableHttpResponse httpResponse;

        try {
            httpResponse = httpClient.execute(requestBuilder.build());
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "\nException thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        try {
            httpResponse.close();
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "\nException thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        StatusLine httpStatusLine = httpResponse.getStatusLine();

        if (httpStatusLine.getStatusCode() != HttpStatus.SC_NO_CONTENT) {
            if (httpStatusLine.getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                throw new AbortException("\nInvalid username or password!");
            } else {
                throw new AbortException(String.format(
                        "\n%s - %s!", httpStatusLine.getStatusCode(), httpStatusLine.getReasonPhrase()
                ));
            }
        }
    }
}
