# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3

import numpy as np
import matplotlib.pyplot as plt
from scipy import stats
import argparse

def main():
    parser = argparse.ArgumentParser("INT plot tool")
    parser.add_argument(
        "-i",
        type=str,
        help="The INT report from int-info tool",
        required=True,
        dest="input_file",
    )
    parser.add_argument(
        "-o",
        type=str,
        help="The output file(png)",
        default="output.png",
        dest="output_file",
    )

    args = parser.parse_args()

    intervals = []
    with open(args.input_file, "r") as f:
        for line in f:
            try:
                interval = float(line) / 1000000000
                intervals.append(interval)
            except ValueError:
                pass  # Ignore lines that doesn't include the number

    max_val = np.max(intervals)
    percentile_of_one_sec = stats.percentileofscore(intervals, 1)
    percentiles = [1, 5, 10, 20, 30, percentile_of_one_sec, 100]
    vlines = np.percentile(intervals, percentiles)

    bins = np.arange(0, max_val + 0.01, 0.01)
    hist, bins = np.histogram(intervals, bins=bins)

    # to percentage
    hist = hist / hist.sum()

    CY = np.cumsum(hist)

    _, ax = plt.subplots(figsize=(10, 10))

    ax.set_xscale("log")
    ax.set_yticks(np.arange(0, 1.1, 0.1))
    ax.hlines(np.arange(0, 1.1, 0.1), 0, max_val, colors="y", linestyles=["dotted"])
    ax.vlines(vlines, 0, 1, colors="green", linestyles=["dotted"])

    ax.plot(bins[:-1], hist)
    ax.plot(bins[:-1], CY, "r--")

    for i in range(0, len(vlines)):
        x = vlines[i]
        y = percentiles[i] / 100
        ax.text(x, y, "({:.2f}%: {:.2f})".format(percentiles[i], x))

    plt.savefig(args.output_file)


if __name__ == "__main__":
    main()
