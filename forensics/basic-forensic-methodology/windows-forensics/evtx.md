# Evtx

The Windows XML EventLog (EVTX) format is used by Microsoft Windows to store system log information. This specification is based the work done by A. Schuster `[SCHUSTER11]` and on `[MS-EVEN6]`. It was complemented by other public available information and was enhanced by analyzing test data.



Chainsaw provides a powerful ‘first-response’ capability to quickly identify threats within Windows event logs. It offers a generic and fast method of searching through event logs for keywords, and by identifying threats using built-in detection logic and via support for Sigma detection rules.



* 🔍 Search and extract event log records by event IDs, string matching, and regex patterns
* 🎯 Hunt for threats using [Sigma](https://github.com/SigmaHQ/sigma) detection rules and custom built-in detection logic
* ⚡ Lightning fast, written in rust, wrapping the [EVTX parser](https://github.com/omerbenamram/evtx) library by [@OBenamram](https://twitter.com/obenamram?lang=en)
* 🔥 Document tagging (detection logic matching) provided by the [TAU Engine](https://github.com/countercept/tau-engine) Library
* 📑 Output in an ASCII table format, CSV format, or JSON format

{% embed url="https://github.com/countercept/chainsaw" %}

```
./chainsaw hunt evtx_attack_samples/ --rules sigma_rules/ --mapping mapping_files/sigma-mapping.yml
```

{% embed url="https://github.com/EricZimmerman/evtx" %}

