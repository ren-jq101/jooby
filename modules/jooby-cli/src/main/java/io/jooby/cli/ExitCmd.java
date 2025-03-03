/**
 * Jooby https://jooby.io
 * Apache License Version 2.0 https://jooby.io/LICENSE.txt
 * Copyright 2014 Edgar Espina
 */
package io.jooby.cli;

import picocli.CommandLine;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Exit console application.
 *
 * @since 2.0.6
 */
@CommandLine.Command(name = "exit", description = "Exit console")
public class ExitCmd extends Cmd {

  @Override public void run(@NonNull Context ctx) {
    ctx.exit(0);
  }
}
