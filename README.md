# wacatac my ass

A command-line tool that enlarges a clean, unsigned Windows executable. The larger file is not
flagged by the Microsoft Defender machine-learning heuristic.

## Purpose

The Microsoft Defender machine-learning heuristic flags small, unsigned, unknown executables as a
`Wacatac` variant, for example `Wacatac.A!ml`, `Wacatac.B!ml`, or `Wacatac.C!ml`. For a clean file,
this result is a false positive. The heuristic does not analyze large files. This tool adds a large data section to a clean file. The file size becomes more than
approximately 100 MiB. The false positive stops.

The tool does not change how the program runs. The tool does not hide code.

This tool is a workaround. It is not a repair. To remove the false positive permanently, sign the
build. A signed build gains reputation over time. The false positive then stops.

## Requirements

- Python 3.6 or later.
- No other packages. The tool uses only the standard library.
- The tool runs on Windows, macOS, and Linux.

## Operation

The tool does these steps:

1. It reads the PE headers of the input file.
2. It adds one or more sections. Each section contains plain text.
3. It writes the output file. The default name is `<name>.padded<ext>`.
4. It corrects the PE checksum.

The text is generated at each run. Two runs do not produce the same bytes. This prevents a fixed
pattern in the output.

## Instructions

To pad a file, enter this command:

    python3 wacatac-my-ass.py mytool.exe

The command writes `mytool.padded.exe`. The default target size is approximately 110 MiB.

Other commands:

    python3 wacatac-my-ass.py mytool.exe --inplace        Overwrite the input file.
    python3 wacatac-my-ass.py -c mytool.exe               Show the file data only. Make no change.
    python3 wacatac-my-ass.py mytool.exe --add-mb 90      Add an exact quantity of data.
    python3 wacatac-my-ass.py --checksum-only mytool.exe  Correct the PE checksum only.

Options: `-o`, `--inplace`, `--total-mb` (default 110), `--add-mb`, `--section` (default `auto`),
and `--force`.

## Section layout

The `--section` option sets the layout of the added data.

- `auto` (default): If the file has no debug sections, the tool uses `debug`. If the file already
  has debug sections, the tool uses `rdata`.
- `debug`: The tool adds several `.debug_*` sections. The file then looks like a build that
  contains debug information.
- `rdata`, `rodata`, `data`, `text`, or `pad`: The tool adds one section with this name.
- A literal name is also permitted, for example `.foo`.

Note: A section named `.pad` can cause a different false positive, for example Avira OPACK. If this
occurs, set a different `--section` value. Then pad the file again.

## Limitations

WARNING: Do not pad a signed file. Padding makes the Authenticode signature invalid. The file then
shows as tampered. Pad the unsigned build first. Then sign the build. The tool refuses a signed
file.

WARNING: Do not pad a file that has data after the last section, for example a self-extracting
installer. Padding can damage this type of file. The tool refuses this type of file. To override
the refusal, use `--force`.

## Verification

After you pad a file, do these steps:

1. Start the file on Windows. Make sure that the program runs.
2. Upload the file to VirusTotal.
3. Wait a few minutes. VirusTotal caches the first result. The Defender machine-learning verdict is
   not immediate. To get the current verdict, press Reanalyze on VirusTotal.

## License

MIT. Refer to the `LICENSE` file.
