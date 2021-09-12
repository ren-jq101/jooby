/**
 * Jooby https://jooby.io
 * Apache License Version 2.0 https://jooby.io/LICENSE.txt
 * Copyright 2014 Edgar Espina
 */
package io.jooby.internal;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

import javax.net.ssl.SSLContext;

import io.jooby.SneakyThrows;
import io.jooby.SslOptions;
import io.jooby.internal.x509.SslContext;

public class SslX509Provider implements SslContextProvider {
  @Override public boolean supports(String type) {
    return SslOptions.X509.equalsIgnoreCase(type);
  }

  @Override public SSLContext create(ClassLoader loader, String provider, SslOptions options) {
    List<Closeable> closeables = new ArrayList<>();
    try {
      InputStream trustCert = getResource(options.getTrustCertificate(), closeables::add);
      InputStream certificate = getResource(options.getCertificate(), closeables::add);
      InputStream privateKey = getResource(options.getPrivateKey(), closeables::add);

      SSLContext context = SslContext
          .newServerContextInternal(provider, trustCert,
              certificate, privateKey, null, 0, 0)
          .context();

      return context;
    } catch (Exception x) {
      throw SneakyThrows.propagate(x);
    } finally {
      IOException cause = null;
      for (Closeable closeable : closeables) {
        try {
          closeable.close();
        } catch (IOException ex) {
          if (cause == null) {
            ex = cause;
          } else {
            cause.addSuppressed(ex);
          }
        }
      }
      if (cause != null) {
        throw SneakyThrows.propagate(cause);
      }
    }
  }

  private InputStream getResource(SneakyThrows.Supplier<InputStream> provider,
      Consumer<InputStream> consumer) {
    InputStream trustCert = Optional.ofNullable(provider)
        .map(SneakyThrows.Supplier::get)
        .orElse(null);
    if (trustCert != null) {
      consumer.accept(trustCert);
    }
    return trustCert;
  }
}
