/**
 * Jooby https://jooby.io
 * Apache License Version 2.0 https://jooby.io/LICENSE.txt
 * Copyright 2014 Edgar Espina
 */
package io.jooby;

import static java.util.Collections.singletonList;
import static java.util.Optional.ofNullable;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.lang.reflect.Type;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

import org.slf4j.Logger;

import io.jooby.exception.RegistryException;
import io.jooby.exception.TypeMismatchException;
import io.jooby.internal.HashValue;
import io.jooby.internal.MissingValue;
import io.jooby.internal.SingleValue;
import io.jooby.internal.UrlParser;
import io.jooby.internal.ValueConverters;

/***
 * Like {@link Context} but with couple of default methods.
 *
 * @since 2.0.2
 * @author edgar
 */
public interface DefaultContext extends Context {

  @NonNull @Override default <T> T require(@NonNull Class<T> type, @NonNull String name)
      throws RegistryException {
    return getRouter().require(type, name);
  }

  @NonNull @Override default <T> T require(@NonNull Class<T> type) throws RegistryException {
    return getRouter().require(type);
  }

  @NonNull @Override default <T> T require(@NonNull ServiceKey<T> key) throws RegistryException {
    return getRouter().require(key);
  }

  @Nullable @Override default <T> T getUser() {
    return (T) getAttributes().get("user");
  }

  @NonNull @Override default Context setUser(@Nullable Object user) {
    getAttributes().put("user", user);
    return this;
  }

  @Override default boolean matches(String pattern) {
    return getRouter().match(pattern, getRequestPath());
  }

  /**
   * Get an attribute by his key. This is just an utility method around {@link #getAttributes()}.
   * This method look first in current context and fallback to application attributes.
   *
   * @param key Attribute key.
   * @param <T> Attribute type.
   * @return Attribute value.
   */
  @Override @Nullable default <T> T attribute(@NonNull String key) {
    T attribute = (T) getAttributes().get(key);
    if (attribute == null) {
      Map<String, Object> globals = getRouter().getAttributes();
      attribute = (T) globals.get(key);
    }
    return attribute;
  }

  @Override @NonNull default Context attribute(@NonNull String key, Object value) {
    getAttributes().put(key, value);
    return this;
  }

  @Override default @NonNull FlashMap flash() {
    return (FlashMap) getAttributes()
        .computeIfAbsent(FlashMap.NAME, key -> FlashMap
            .create(this, getRouter().getFlashCookie().clone()));
  }

  /**
   * Get a flash attribute.
   *
   * @param name Attribute's name.
   * @return Flash attribute.
   */
  @Override default @NonNull Value flash(@NonNull String name) {
    return Value.create(this, name, flash().get(name));
  }

  @Override default @NonNull Value session(@NonNull String name) {
    Session session = sessionOrNull();
    if (session != null) {
      return session.get(name);
    }
    return Value.missing(name);
  }

  @Override default @NonNull Session session() {
    Session session = sessionOrNull();
    if (session == null) {
      SessionStore store = getRouter().getSessionStore();
      session = store.newSession(this);
      getAttributes().put(Session.NAME, session);
    }
    return session;
  }

  @Override default @Nullable Session sessionOrNull() {
    Session session = (Session) getAttributes().get(Session.NAME);
    if (session == null) {
      Router router = getRouter();
      SessionStore store = router.getSessionStore();
      session = store.findSession(this);
      if (session != null) {
        getAttributes().put(Session.NAME, session);
      }
    }
    return session;
  }

  @Override default @NonNull Context forward(@NonNull String path) {
    setRequestPath(path);
    getRouter().match(this).execute(this);
    return this;
  }

  @Override default @NonNull Value cookie(@NonNull String name) {
    String value = cookieMap().get(name);
    return value == null ? Value.missing(name) : Value.value(this, name, value);
  }

  @Override @NonNull default Value path(@NonNull String name) {
    String value = pathMap().get(name);
    return value == null
        ? new MissingValue(name)
        : new SingleValue(this, name, UrlParser.decodePathSegment(value));
  }

  @Override @NonNull default <T> T path(@NonNull Class<T> type) {
    return path().to(type);
  }

  @Override @NonNull default ValueNode path() {
    HashValue path = new HashValue(this, null);
    for (Map.Entry<String, String> entry : pathMap().entrySet()) {
      path.put(entry.getKey(), entry.getValue());
    }
    return path;
  }

  @Override @NonNull default ValueNode query(@NonNull String name) {
    return query().get(name);
  }

  @Override @NonNull default String queryString() {
    return query().queryString();
  }

  @Override @NonNull default <T> T query(@NonNull Class<T> type) {
    return query().to(type);
  }

  @Override @NonNull default Map<String, String> queryMap() {
    return query().toMap();
  }

  @Override @NonNull default Map<String, List<String>> queryMultimap() {
    return query().toMultimap();
  }

  @Override @NonNull default Value header(@NonNull String name) {
    return header().get(name);
  }

  @Override @NonNull default Map<String, String> headerMap() {
    return header().toMap();
  }

  @Override @NonNull default Map<String, List<String>> headerMultimap() {
    return header().toMultimap();
  }

  @Override default boolean accept(@NonNull MediaType contentType) {
    return Objects.equals(accept(singletonList(contentType)), contentType);
  }

  @Override default MediaType accept(@NonNull List<MediaType> produceTypes) {
    Value accept = header(ACCEPT);
    if (accept.isMissing()) {
      // NO header? Pick first, which is the default.
      return produceTypes.isEmpty() ? null : produceTypes.get(0);
    }

    // Sort accept by most relevant/specific first:
    List<MediaType> acceptTypes = accept.toList().stream()
        .flatMap(value -> MediaType.parse(value).stream())
        .distinct()
        .sorted()
        .collect(Collectors.toList());

    // Find most appropriated type:
    int idx = Integer.MAX_VALUE;
    MediaType result = null;
    for (MediaType produceType : produceTypes) {
      for (int i = 0; i < acceptTypes.size(); i++) {
        MediaType acceptType = acceptTypes.get(i);
        if (produceType.matches(acceptType)) {
          if (i < idx) {
            result = produceType;
            idx = i;
            break;
          }
        }
      }
    }
    return result;
  }

  @Override default @NonNull String getRequestURL() {
    return getRequestURL(getRequestPath() + queryString());
  }

  @Override default @NonNull String getRequestURL(@NonNull String path) {
    String scheme = getScheme();
    String host = getHost();
    int port = getPort();
    StringBuilder url = new StringBuilder();
    url.append(scheme).append("://").append(host);
    if (port > 0 && port != PORT && port != SECURE_PORT) {
      url.append(":").append(port);
    }
    String contextPath = getContextPath();
    if (!contextPath.equals("/") && !path.startsWith(contextPath)) {
      url.append(contextPath);
    }
    url.append(path);

    return url.toString();
  }

  @Override @Nullable default MediaType getRequestType() {
    Value contentType = header("Content-Type");
    return contentType.isMissing() ? null : MediaType.valueOf(contentType.value());
  }

  @Override @NonNull default MediaType getRequestType(MediaType defaults) {
    Value contentType = header("Content-Type");
    return contentType.isMissing() ? defaults : MediaType.valueOf(contentType.value());
  }

  @Override default long getRequestLength() {
    Value contentLength = header("Content-Length");
    return contentLength.isMissing() ? -1 : contentLength.longValue();
  }

  @Override default @Nullable String getHostAndPort() {
    Optional<String> header = getRouter().isTrustProxy()
        ? header("X-Forwarded-Host").toOptional()
        : Optional.empty();
    String value = header
        .orElseGet(() ->
            ofNullable(header("Host").valueOrNull())
                .orElseGet(() -> getServerHost() + ":" + getServerPort())
        );
    int i = value.indexOf(',');
    String host = i > 0 ? value.substring(0, i).trim() : value;
    if (host.startsWith("[") && host.endsWith("]")) {
      return host.substring(1, host.length() - 1).trim();
    }
    return host;
  }

  @Override default @NonNull String getServerHost() {
    String host = getRouter().getServerOptions().getHost();
    return host.equals("0.0.0.0") ? "localhost" : host;
  }

  @Override default int getServerPort() {
    ServerOptions options = getRouter().getServerOptions();
    return isSecure()
        // Buggy proxy where it report a https scheme but there is no HTTPS configured option
        ? ofNullable(options.getSecurePort()).orElse(options.getPort())
        : options.getPort();
  }

  @Override default int getPort() {
    String hostAndPort = getHostAndPort();
    if (hostAndPort != null) {
      int index = hostAndPort.indexOf(':');
      if (index > 0) {
        return Integer.parseInt(hostAndPort.substring(index + 1));
      }
      return isSecure() ? SECURE_PORT : PORT;
    }
    return getServerPort();
  }

  @Override default @NonNull String getHost() {
    String hostAndPort = getHostAndPort();
    if (hostAndPort != null) {
      int index = hostAndPort.indexOf(':');
      return index > 0 ? hostAndPort.substring(0, index).trim() : hostAndPort;
    }
    return getServerHost();
  }

  @Override default boolean isSecure() {
    return getScheme().equals("https");
  }

  @Override @NonNull default Map<String, List<String>> formMultimap() {
    return form().toMultimap();
  }

  @Override @NonNull default Map<String, String> formMap() {
    return form().toMap();
  }

  @Override @NonNull default ValueNode form(@NonNull String name) {
    return form().get(name);
  }

  @Override @NonNull default <T> T form(@NonNull Class<T> type) {
    return form().to(type);
  }

  @Override @NonNull default ValueNode multipart(@NonNull String name) {
    return multipart().get(name);
  }

  @Override @NonNull default <T> T multipart(@NonNull Class<T> type) {
    return multipart().to(type);
  }

  @Override @NonNull default Map<String, List<String>> multipartMultimap() {
    return multipart().toMultimap();
  }

  @Override @NonNull default Map<String, String> multipartMap() {
    return multipart().toMap();
  }

  @Override @NonNull default List<FileUpload> files() {
    return multipart().files();
  }

  @Override @NonNull default List<FileUpload> files(@NonNull String name) {
    return multipart().files(name);
  }

  @Override @NonNull default FileUpload file(@NonNull String name) {
    return multipart().file(name);
  }

  @Override default @NonNull <T> T body(@NonNull Class<T> type) {
    return body().to(type);
  }

  @Override default @NonNull <T> T body(@NonNull Type type) {
    return body().to(type);
  }

  @Override default @NonNull <T> T convert(@NonNull ValueNode value, @NonNull Class<T> type) {
    T result = ValueConverters.convert(value, type, getRouter());
    if (result == null) {
      throw new TypeMismatchException(value.name(), type);
    }
    return result;
  }

  @Override default @NonNull <T> T decode(@NonNull Type type, @NonNull MediaType contentType) {
    try {
      if (MediaType.text.equals(contentType)) {
        T result = ValueConverters.convert(body(), type, getRouter());
        return result;
      }
      return (T) decoder(contentType).decode(this, type);
    } catch (Exception x) {
      throw SneakyThrows.propagate(x);
    }
  }

  @Override default @NonNull MessageDecoder decoder(@NonNull MediaType contentType) {
    return getRoute().decoder(contentType);
  }

  @Override @NonNull default Context setResponseHeader(@NonNull String name, @NonNull Date value) {
    return setResponseHeader(name, RFC1123.format(Instant.ofEpochMilli(value.getTime())));
  }

  @Override @NonNull
  default Context setResponseHeader(@NonNull String name, @NonNull Instant value) {
    return setResponseHeader(name, RFC1123.format(value));
  }

  @Override @NonNull
  default Context setResponseHeader(@NonNull String name, @NonNull Object value) {
    if (value instanceof Date) {
      return setResponseHeader(name, (Date) value);
    }
    if (value instanceof Instant) {
      return setResponseHeader(name, (Instant) value);
    }
    return setResponseHeader(name, value.toString());
  }

  @Override @NonNull default Context setResponseType(@NonNull MediaType contentType) {
    return setResponseType(contentType, contentType.getCharset());
  }

  @Override @NonNull default Context setResponseCode(@NonNull StatusCode statusCode) {
    return setResponseCode(statusCode.value());
  }

  @Override default @NonNull Context render(@NonNull Object value) {
    try {
      Route route = getRoute();
      MessageEncoder encoder = route.getEncoder();
      byte[] bytes = encoder.encode(this, value);
      if (bytes == null) {
        if (!isResponseStarted()) {
          throw new IllegalStateException("The response was not encoded");
        }
      } else {
        send(bytes);
      }
      return this;
    } catch (Exception x) {
      throw SneakyThrows.propagate(x);
    }
  }

  @Override default @NonNull OutputStream responseStream(@NonNull MediaType contentType) {
    setResponseType(contentType);
    return responseStream();
  }

  @Override default @NonNull Context responseStream(@NonNull MediaType contentType,
      @NonNull SneakyThrows.Consumer<OutputStream> consumer) throws Exception {
    setResponseType(contentType);
    return responseStream(consumer);
  }

  @Override default @NonNull Context responseStream(
      @NonNull SneakyThrows.Consumer<OutputStream> consumer)
      throws Exception {
    try (OutputStream out = responseStream()) {
      consumer.accept(out);
    }
    return this;
  }

  @Override default @NonNull PrintWriter responseWriter() {
    return responseWriter(MediaType.text);
  }

  @Override default @NonNull PrintWriter responseWriter(@NonNull MediaType contentType) {
    return responseWriter(contentType, contentType.getCharset());
  }

  @Override default @NonNull Context responseWriter(
      @NonNull SneakyThrows.Consumer<PrintWriter> consumer)
      throws Exception {
    return responseWriter(MediaType.text, consumer);
  }

  @Override default @NonNull Context responseWriter(@NonNull MediaType contentType,
      @NonNull SneakyThrows.Consumer<PrintWriter> consumer) throws Exception {
    return responseWriter(contentType, contentType.getCharset(), consumer);
  }

  @Override default @NonNull Context responseWriter(@NonNull MediaType contentType,
      @Nullable Charset charset,
      @NonNull SneakyThrows.Consumer<PrintWriter> consumer) throws Exception {
    try (PrintWriter writer = responseWriter(contentType, charset)) {
      consumer.accept(writer);
    }
    return this;
  }

  @Override default @NonNull Context sendRedirect(@NonNull String location) {
    return sendRedirect(StatusCode.FOUND, location);
  }

  @Override default @NonNull Context sendRedirect(@NonNull StatusCode redirect,
      @NonNull String location) {
    setResponseHeader("location", location);
    return send(redirect);
  }

  @Override default @NonNull Context send(@NonNull byte[]... data) {
    ByteBuffer[] buffer = new ByteBuffer[data.length];
    for (int i = 0; i < data.length; i++) {
      buffer[i] = ByteBuffer.wrap(data[i]);
    }
    return send(buffer);
  }

  @Override default @NonNull Context send(@NonNull String data) {
    return send(data, StandardCharsets.UTF_8);
  }

  @Override default @NonNull Context send(@NonNull FileDownload file) {
    setResponseHeader("Content-Disposition", file.getContentDisposition());
    InputStream content = file.stream();
    long length = file.getFileSize();
    if (length > 0) {
      setResponseLength(length);
    }
    setDefaultResponseType(file.getContentType());
    if (content instanceof FileInputStream) {
      send(((FileInputStream) content).getChannel());
    } else {
      send(content);
    }
    return this;
  }

  @Override default @NonNull Context send(@NonNull Path file) {
    try {
      setDefaultResponseType(MediaType.byFile(file));
      return send(FileChannel.open(file));
    } catch (IOException x) {
      throw SneakyThrows.propagate(x);
    }
  }

  @Override @NonNull default Context sendError(@NonNull Throwable cause) {
    sendError(cause, getRouter().errorCode(cause));
    return this;
  }

  /**
   * Send an error response. This method set the  error code.
   *
   * @param cause Error. If this is a fatal error it is going to be rethrow it.
   * @param code Default error code.
   * @return This context.
   */
  @Override @NonNull default Context sendError(@NonNull Throwable cause,
      @NonNull StatusCode code) {
    Router router = getRouter();
    Logger log = router.getLog();
    if (isResponseStarted()) {
      log.error(ErrorHandler.errorMessage(this, code), cause);
    } else {
      try {
        if (getResetHeadersOnError()) {
          removeResponseHeaders();
        }
        // set default error code
        setResponseCode(code);
        router.getErrorHandler().apply(this, cause, code);
      } catch (Exception x) {
        if (!isResponseStarted()) {
          // edge case when there is a bug in a the error handler (probably custom error) what we
          // do is to use the default error handler
          ErrorHandler.create().apply(this, cause, code);
        }
        if (Server.connectionLost(x)) {
          log.debug("error handler resulted in a exception while processing `{}`", cause.toString(),
              x);
        } else {
          log.error("error handler resulted in a exception while processing `{}`", cause.toString(),
              x);
        }
      }
    }
    /** rethrow fatal exceptions: */
    if (SneakyThrows.isFatal(cause)) {
      throw SneakyThrows.propagate(cause);
    }
    return this;
  }
}
