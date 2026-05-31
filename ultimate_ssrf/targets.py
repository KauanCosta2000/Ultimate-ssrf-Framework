import re
import sys
from typing import List, Optional

from .utils import FAIL


class TargetManager:
    @staticmethod
    def from_args(args) -> List[str]:
        if args.target:
            cleaned = TargetManager._clean(args.target)
            return [cleaned] if cleaned else []

        if args.targets:
            return [
                domain
                for domain in (TargetManager._clean(item) for item in args.targets.split(","))
                if domain
            ]

        if args.target_file:
            return TargetManager._from_file(args.target_file)

        return []

    @staticmethod
    def _clean(domain: str) -> Optional[str]:
        value = domain.strip()

        if not value:
            return None

        value = re.sub(r"^https?://", "", value).split("/")[0]

        return value

    @staticmethod
    def _from_file(path: str) -> List[str]:
        targets = []

        try:
            with open(path, encoding="utf-8") as file:
                for line in file:
                    line = line.strip()

                    if line and not line.startswith("#"):
                        cleaned = TargetManager._clean(line)

                        if cleaned:
                            targets.append(cleaned)

        except Exception as error:
            print(f"{FAIL} Error reading target file '{path}': {error}")
            sys.exit(1)

        return targets

    @staticmethod
    def interactive() -> List[str]:
        print("\nTARGET SELECTION")
        print("  1 - Single domain")
        print("  2 - Multiple domains")
        print("  3 - File")

        while True:
            choice = input("Choose [1/2/3]: ").strip()

            if choice == "1":
                target = TargetManager._clean(input("Domain: "))
                return [target] if target else []

            if choice == "2":
                domains = input("Domains separated by comma: ")
                return [
                    domain
                    for domain in (TargetManager._clean(item) for item in domains.split(","))
                    if domain
                ]

            if choice == "3":
                return TargetManager._from_file(input("File path: ").strip())

            print(f"{FAIL} Invalid option")
