import argparse


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="authlog-watch",
        description="Review Linux auth.log SSH events.",
    )
    parser.add_argument("path", help="Path to an auth.log-style file")
    args = parser.parse_args()

    print(f"authlog-watch will scan {args.path}")
