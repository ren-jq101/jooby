/**
 * Jooby https://jooby.io
 * Apache License Version 2.0 https://jooby.io/LICENSE.txt
 * Copyright 2014 Edgar Espina
 */
package io.jooby.cli;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.jooby.internal.cli.CommandContextImpl;
import io.jooby.internal.cli.JLineCompleter;
import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.ParsedLine;
import org.jline.reader.UserInterruptException;
import org.jline.reader.impl.DefaultParser;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import picocli.CommandLine;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Application console.
 *
 * Usage:
 * <pre>{@code
 * jooby> --help
 * Usage: jooby [-hV] [COMMAND]
 *   -h, --help      Show this help message and exit.
 *   -V, --version   Print version information and exit.
 * Commands:
 *   create  Creates a new application
 *   exit    Exit console
 * }</pre>
 *
 * @since 2.0.6
 */
@CommandLine.Command(
    name = "jooby",
    versionProvider = Version.class,
    mixinStandardHelpOptions = true,
    version = "Print version information"
)
public class Cli extends Cmd {
  /** JSON parser. */
  public static final Gson gson = new GsonBuilder()
      .create();

  /** Command line specification.  */
  private @CommandLine.Spec CommandLine.Model.CommandSpec spec;

  /** Unmatched command line arguments. */
  private @CommandLine.Unmatched List<String> args;

  @Override public void run(@NonNull Context ctx) {
    List<String> args = this.args.stream()
        .filter(Objects::nonNull)
        .map(String::trim)
        .filter(it -> it.length() > 0)
        .collect(Collectors.toList());
    if (args.size() > 0) {
      String arg = args.get(0);
      if ("-h".equals(arg) || "--help".equals(arg)) {
        ctx.println(spec.commandLine().getUsageMessage());
      } else if ("-V".equalsIgnoreCase(arg) || "--version".equals(arg)) {
        ctx.println(ctx.getVersion());
      } else {
        ctx.println("Unknown command or option(s): " + args.stream().collect(Collectors.joining(" ")));
        ctx.println("  " + ctx);
        ctx.println(spec.commandLine().getUsageMessage());
      }
    } else {
      ctx.println(spec.commandLine().getUsageMessage());
    }
  }

  /**
   * Start a jooby console or execute given arguments and exits.
   *
   * @param args Command line arguments.
   * @throws IOException If something goes wrong.
   */
  public static void main(String[] args) throws IOException {
    // set up the completion
    Cli jooby = new Cli();
    CommandLine cmd = new CommandLine(jooby)
        .addSubcommand(new CreateCmd())
        .addSubcommand(new ExitCmd())
        .addSubcommand(new SetCmd());

    Terminal terminal = TerminalBuilder.builder().build();
    LineReader reader = LineReaderBuilder.builder()
        .terminal(terminal)
        .completer(new JLineCompleter(cmd.getCommandSpec()))
        .parser(new DefaultParser())
        .build();

    CommandContextImpl context = new CommandContextImpl(reader, Version.VERSION);
    jooby.setContext(context);
    cmd.getSubcommands().values().stream()
        .map(CommandLine::getCommand)
        .filter(Cmd.class::isInstance)
        .map(Cmd.class::cast)
        .forEach(command -> command.setContext(context));

    if (args.length > 0) {
      cmd.execute(args);
    } else {
      String prompt = "jooby> ";

      // start the shell and process input until the user quits with Ctl-D
      while (true) {
        try {
          String line = reader.readLine(prompt);
          ParsedLine pl = reader.getParser().parse(line, 0);
          String[] arguments = pl.words().toArray(new String[0]);
          cmd.execute(arguments);
        } catch (UserInterruptException e) {
          System.exit(0);
        } catch (EndOfFileException e) {
          return;
        }
      }
    }
  }
}
