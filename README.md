# Falcon-Crowdstrike-Events-Processor
This project process Falcon Crowdstrike logs available in .csv format.

The result of processing will be split by agent ID (host).

Every section of agent ID will include the authentication attempts (successful and failed) on the system and the process tree.

At the end of the output, there is a list of process IDs and thread IDs that are extracted from the processed logs (including the parent process IDs and thread IDs) that can be used in the SIEM to search for any additional results if that's needed.

The same output of the process tree is saved in a JSON format inside the `~/Documents/EDR-Process-Explorer/web/flare.json` file in case you want to use this project [github.com/mohamedaymenkarmous/EDR-Process-Explorer](https://github.com/mohamedaymenkarmous/EDR-Process-Explorer) later to show the graphical process tree in a web page.

# Setup
The web page can work only inside a web service. You can install any web service you like and then you need to place the content of the `src` directorry inside the `www` directory.
If you don't want to install anything, you can setup the web service in python using the following command:
```sh
pip3 install --upgrade pip
pip3 install pandas
git clone https://github.com/mohamedaymenkarmous/Falcon-Crowdstrike-Events-Processor
python3 ~/Documents/Falcon-Crowdstrike-Events-Processor/main.py --help
```

And next time you want to process the .csv logs downloaded from your SIEM and you need to configure the [config.json](config.json) configuration file to map the Falcon Crowdstrike event log names with the field names known in your SIEM (available in the .csv file) (please change only the values, not the keys) and then you need to run the following command:

```sh
python3 ~/Documents/Falcon-Crowdstrike-Events-Processor/main.py --file YOUR_CSV_FILE.csv
```

# Support
This is an open source for any person who wants to contribute. Feel free to suggest any feature either verbally by creating a Github Issue or technically with a Pull Request.
