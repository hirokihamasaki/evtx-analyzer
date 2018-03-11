#!/usr/bin/env python
import Evtx.Evtx as evtx
import Evtx.Views as e_views


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Dump EVTX file into XML.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX file")
    args = parser.parse_args()

    with evtx.Evtx(args.evtx) as log:
        for record in log.records():
            print(record.xml())

if __name__ == "__main__":
    main()
