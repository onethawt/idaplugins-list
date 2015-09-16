# A list of IDA Plugins

* [Adobe Flash disassembler](https://hex-rays.com/contests/2009/SWF/ReadMe.txt): The 2 plugins present in this archive will enable IDA to parse SWF files, load all SWF tags as segments for fast search and retrieval, parse all tags that can potentially contain ActionScript2 code, discover all such code(a dedicated processor module has been written for it) and even name the event functions acording to event handled in it (eg. OnInitialize). [Download](https://hex-rays.com/contests/2009/SWF/swf.zip)

* [Bin Sourcerer](https://github.com/BinSigma/BinSourcerer): BinSourcerer (a.k.a RE-Source Online) is an assembly to source code matching framework for binary auditing and malware analysis.

* [collabREate](http://www.idabook.com/collabreate/): collabREate is a plugin for IDA Pro that is designed to provide a collaborative reverse engineering capability for multiple IDA users working on the same binary file.

* [Class Informer](http://www.openrce.org/blog/view/1344/Class_Informer_IDA_plug-in): Scans an MSVC 32bit target IDB for vftables with C++ RTTI, and MFC RTCI type data. Places structure defs, names, labels, and comments to make more sense of class vftables ("Virtual Function Table") and make them read easier as an aid to reverse engineering. Creates a list window with found vftables for browsing.

* [Crowd Detox](https://github.com/CrowdStrike/CrowdDetox): The CrowdDetox plugin for Hex-Rays automatically removes junk code and variables from Hex-Rays function decompilations.

* [Data Xref Counter](https://github.com/onethawt/idapyscripts): Enumerates all of the the x-references in a specific segment and counts the frequency of usage. The plugin displays the data in QtTableWidget and lets the user filter and sort the references. You can also export the data to a CSV file.

* [Diaphora](https://github.com/joxeankoret/diaphora): Diaphora (διαφορά, Greek for 'difference') is a program diffing plugin for IDA Pro, similar to Zynamics Bindiff or the FOSS counterparts DarunGrim, TurboDiff, etc... It was released during SyScan 2015.

* [DWARF Plugin](https://hex-rays.com/contests/2009/IDADwarf-0.2/README): IDADWARF is an IDA plugin that imports DWARF debugging symbols into an IDA database. [Download](https://hex-rays.com/contests/2009/IDADwarf-0.2/idadwarf-0.2.zip)

* [Flare Plugins](https://github.com/fireeye/flare-ida): Shellcode Hashes, Struct Typer, StackStrings, MSDN Annotations, ApplyCalleType

* [Funcap](https://github.com/deresz/funcap): This script records function calls (and returns) across an executable using IDA debugger API, along with all the arguments passed. It dumps the info to a text file, and also inserts it into IDA's inline comments. This way, static analysis that usually follows the behavioral runtime analysis when analyzing malware, can be directly fed with runtime info such as decrypted strings returned in function's arguments.

* [Graph Slick](https://github.com/lallousx86/GraphSlick): Automated detection of inlined functions. It highlights similar groups of nodes and allows you to group them, simplifying complex functions. The authors provide an accompanying presentation which explains the algorithms behind the plugin and shows sample use cases.

* [HexRays CodeXplorer](https://github.com/REhints/HexRaysCodeXplorer): The Hex-Rays Decompiler plugin for better code navigation in RE process. CodeXplorer automates code REconstruction of C++ applications or modern malware like Stuxnet, Flame, Equation, Animal Farm ...

* [HexRays Tools](https://github.com/nihilus/hexrays_tools): 
  * Assist in creation of new structure definitions / virtual calls detection
  * Jump directly to virtual function or structure member definition
  * Gives list of structures with given size, with given offset
  * Finds structures with same "shape" as is used.
  * convert function to __usercall or __userpurge
  * and more....

* [IDA2SQL](https://github.com/zynamics/ida2sql-plugin-ida): As the name implies this plugin can be used to export information from IDA databases to SQL databases. This allows for further analysis of the collected data: statstical analysis, building graphs, finding similarities between programs, etc.

* [IDA Eye](http://www.mfmokbel.com/Down/RCE/Documentation.html): Plugin that enables you to perform different operations at the mnemonic level, independent of any particular processor type. These operations are facilitated through a parameterized template, which include the capabilities to de/highlight instructions, gather statistical information about the frequency of each instruction, and search for sequences of mnemonics, among other features.

* [IDA Scope](https://bitbucket.org/daniel_plohmann/simplifire.idascope): IDAscope is an IDA Pro extension with the goal to ease the task of (malware) reverse engineering with a current focus on x86 Windows. It consists of multiple tabs, containing functionality to achieve different goals such as fast identification of semantically interesting locations in the analysis target, seamless access to MSDN documentation of Windows API, and finding of potential crypto/compression algorithms.

* [IDA Sploiter](http://thesprawl.org/projects/ida-sploiter/): IDA Sploiter is a plugin for Hex-Ray's IDA Pro disassembler designed to enhance IDA's capabilities as an exploit development and vulnerability research tool. Some of the plugin's features include a powerful ROP gadgets search engine, semantic gadget analysis and filtering, interactive ROP chain builder, stack pivot analysis, writable function pointer search, cyclic memory pattern generation and offset analysis, detection of bad characters and memory holes, and many others.

* [IDA Stealth](http://newgre.net/idastealth): IDAStealth is a plugin which aims to hide the IDA debugger from most common anti-debugging techniques. The plugin is composed of two files, the plugin itself and a dll which is injected into the debuggee as soon as the debugger attaches to the process. The injected dll actually implements most of the stealth techniques either by hooking system calls or by patching some flags in the remote process.

* [IDA Toolbag](https://github.com/aaronportnoy/toolbag): The IDA Toolbag plugin provides many handy features, such as:
  * A 'History' view, that displays functions in the disassembly that you have decided are important, and the relationships between them.
  * A code path-searching tool, that lets you find what functions (or blocks) are forming a path between two locations.
  * Manage and run your IDC/Python scripts
  * Something that's also of considerable importance is that the IDA Toolbag lets you collaborate with other IDA users: one can publish his 'History', or import another user's history & even merge them!
  * See the official documentation for an extensive feature list.

* [MyNav](https://code.google.com/p/mynav/): MyNav is a plugin for IDA Pro to help reverse engineers in the most typical task like discovering what functions are responsible of some specifical tasks, finding paths between "interesting" functions and data entry points.

* [Optimice](https://code.google.com/p/optimice/): This plugin enables you to remove some common obfuscations and rewrite code to a new segment. Currently supported optimizations are: Dead code removal, JMP merging, JCC opaque predicate removal, Pattern based deobfuscations

* [X86Emu](http://www.idabook.com/ida-x86emu/):  Its purpose is to allow a reverse engineer the chance to step through x86 code while reverse engineering a binary.  The plugin can help you step through any x86 binary from any platform. For Windows binaries, many common library calls are trapped and emulated by the emulator, allowing for a higher fidelity emulation. I find it particularly useful for stepping through obfuscated code as it automatically reorganizes an IDA disassembly based on actual code paths.

## Commercial Plugins

* [Zynamics BinDiff](http://www.zynamics.com/bindiff.html): BinDiff is a comparison tool for binary files, that assists vulnerability researchers and engineers to quickly find differences and similarities in disassembled code.

