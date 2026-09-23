/*
 * Skald
 *
 * Copyright (C) 2026 Gard Kroken
 *
 * Built on ShinyProxy, Copyright (C) 2016-2026 Open Analytics NV.
 *
 * ===========================================================================
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Apache License as published by
 * The Apache Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Apache License for more details.
 *
 * You should have received a copy of the Apache License
 * along with this program.  If not, see <http://www.apache.org/licenses/>
 */
package eu.openanalytics.shinyproxy.publisher.bundle;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The corpus oracle's subject contract, spoken by {@link BundleExtractor}.
 *
 * <p>{@code dev/bundle-oracle.py} judges any program that takes
 * {@code --root DIR --archive FILE --limits JSON} and prints one JSON verdict. Until this
 * existed it could only judge the disposable reference extractor, so the independent corpus
 * said nothing about the extractor that ships. This is test code on purpose: it needs the
 * package-private {@link BundleExtractor#extractInto} and {@link ExtractionRoot#adopt}, and
 * nothing in production has a reason to extract into a directory it did not create.
 *
 * <p><b>What it translates, and what it does not.</b>
 * <ul>
 *   <li>The oracle's root already exists. It is adopted through the same parent-descriptor,
 *       no-follow, identity and permission checks that end {@link ExtractionRoot#createUnder}
 *       — only the create is skipped. A root handed over as a symlink is therefore refused by
 *       production code, not by this adapter.</li>
 *   <li>The declared upload size is passed, as the upload endpoint will, so the pre-parse
 *       size check is judged too.</li>
 *   <li>On acceptance the manifest bytes the extractor returned are written to
 *       {@code manifest.json} in the root, because that is where the oracle looks for the
 *       inventory it checks the payload against. The extractor never writes it there itself
 *       (see {@link BundleExtractor}). The write is create-new and no-follow; if a payload
 *       file already holds that name the verdict is a crash naming the adapter, never a
 *       silent overwrite of the thing being judged.</li>
 * </ul>
 *
 * <p>Exit status is 0 whenever a verdict was printed, whatever it says. A rejection is a
 * verdict; an exception that is not a {@link BundleRejection} is reported as a crash, which
 * the oracle never counts as a rejection.
 */
public final class BundleExtractorCli {

    private BundleExtractorCli() {
    }

    public static void main(String[] args) throws IOException {
        Path root = null;
        Path archive = null;
        String limitsJson = null;
        for (int i = 0; i + 1 < args.length; i += 2) {
            switch (args[i]) {
                case "--root" -> root = Path.of(args[i + 1]);
                case "--archive" -> archive = Path.of(args[i + 1]);
                case "--limits" -> limitsJson = args[i + 1];
                default -> usage("unknown argument " + args[i]);
            }
        }
        if (root == null || archive == null || limitsJson == null || args.length % 2 != 0) {
            usage("--root, --archive and --limits are all required");
        }

        Map<String, Object> verdict = new LinkedHashMap<>();
        try {
            ExtractionLimits limits = ExtractionLimits.fromJson(limitsJson);
            long size = Files.size(archive);
            GzipMember.checkUploadSize(size, limits);
            try (InputStream upload = Files.newInputStream(archive);
                 ExtractionRoot adopted = adopt(root)) {
                BundleExtractor.Extracted extracted = BundleExtractor.extractInto(adopted,
                        upload, limits, System::nanoTime);
                writeManifestForTheOracle(root, extracted.manifest());
                verdict.put("decision", "accept");
                verdict.put("rule", "");
                verdict.put("reason", "");
                verdict.put("entries", extracted.files());
                verdict.put("bytes", extracted.bytes());
            }
        } catch (BundleRejection rejection) {
            verdict.put("decision", "reject");
            verdict.put("rule", rejection.rule().name());
            verdict.put("reason", rejection.getMessage());
        } catch (Throwable crash) {
            verdict.clear();
            verdict.put("decision", "crash");
            verdict.put("rule", crash.getClass().getSimpleName());
            String message = String.valueOf(crash.getMessage());
            verdict.put("reason", message.substring(0, Math.min(200, message.length())));
        }
        System.out.println(new ObjectMapper().writeValueAsString(verdict));
    }

    /** {@link ExtractionRoot#createUnder} without the create. */
    private static ExtractionRoot adopt(Path root) throws IOException {
        Path absolute = root.toAbsolutePath();
        Object key = Files.readAttributes(absolute, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS).fileKey();
        DirectoryStream<Path> parent = Files.newDirectoryStream(absolute.getParent());
        ExtractionRoot.requireDescriptorRelative(parent);
        return ExtractionRoot.adopt((SecureDirectoryStream<Path>) parent, absolute,
                absolute.getFileName().toString(), key);
    }

    private static void writeManifestForTheOracle(Path root, byte[] manifest)
            throws IOException {
        try {
            Files.write(root.resolve("manifest.json"), manifest,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS);
        } catch (java.nio.file.FileAlreadyExistsException ex) {
            throw new IllegalStateException("adapter collision: the payload already has a"
                    + " manifest.json at its root, where this adapter puts the bundle"
                    + " manifest for the oracle; refusing to overwrite what is being judged");
        }
    }

    private static void usage(String problem) {
        System.err.println(problem + "\nusage: BundleExtractorCli --root DIR --archive FILE"
                + " --limits JSON");
        System.exit(2);
    }
}
