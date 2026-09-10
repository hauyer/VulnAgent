"""Non-executing entry point marker for the source-analysis sample."""

from vulnerable import command_injection


def main() -> None:
    command_injection()


if __name__ == "__main__":
    main()
