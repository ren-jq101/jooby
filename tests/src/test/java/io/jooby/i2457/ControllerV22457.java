package io.jooby.i2457;


import io.jooby.annotations.GET;
import io.jooby.annotations.Path;

@Path("/")
public class ControllerV22457 {

  @javax.inject.Inject // Guice does not support jakarta inject yet.
  private WelcomeService2457 welcomeService;

  @GET("/welcome")
  public String sayHi() {
    return welcomeService.welcome("v2");
  }
}
