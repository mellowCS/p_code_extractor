# p_code_extractor
This script extracts the raw Pcode from Ghidra and puts it into dedicated Object which are then
serialised using Gson. The result is a Json file containing the processed binary as Pcode Objects.

## Use

##### IMPORTANT:
You need the third party library gson which is available at Maven Central
```
https://search.maven.org/artifact/com.google.code.gson/gson/2.8.6/jar
```
When running the script for the first time, remember to call it with the `--gson` flag which
automatically moves the gson library to the `.../.ghidra/.ghidra_9.X.X_PUBLIC/plugins/` directory
and the `--plugin` flag to identify the location of `.../.ghidra/.ghidra_9.X.X_PUBLIC/`.
In case the `plugins` directory does not exist, it is created automatically.

The script `start_analysis.py` is used to call `PcodeExtractor.java`. It is necessary to pass the location of ghidra via the `--ghidra` flag and the location of the input binary via the `--import` flag.

Each time the script is called, it creates a new Ghidra project in a `tmp` folder in this project's root directory. The project is then deleted after the binary has been processed. The resulting Json file is then also put into the `tmp` folder.

#### Example

```
python3 start_analysis.py --gson $Home/gson-2.8.6.jar --plugin $HOME/.ghidra/.ghidra_9.1.2_PUBLIC/
--ghidra $HOME/ghidra_9.1.2_PUBLIC/ --import $HOME/<binary>
