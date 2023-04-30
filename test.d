import std.file, std.path, std.array, std.algorithm, std.string, std.utf;
import std.stdio : writeln;

bool contains(string lines, string path) {
	auto result = lines.findSplit(path);
    return result[1] == path;
}

string[] GetAllAsasm() {
    string[] files;
    foreach (asasm; dirEntries("./158-0/", SpanMode.shallow).array()) {
        if (asasm.isFile && contains(asasm.name,"class")) {
            files ~= asasm.name;
        }
    }
    return files;
}

string GetClassNameByFile(string file) {
    return file.replace("\\", "/").split("/")[$ - 1].split('.')[0].replace("%", "\\x");
}

string GetPathByName(string name) {
    return "./158-0/"~name.replace("\\x", "%")~".class.asasm";
}

string[] ReadAllLines(string path) {
    return ReadAllText(path).splitter("\n").array;
}

string ReadAllText(string path) {
    return cast(string) read(path.replace("\\x", "%"));
}

void WriteAllLines(string path, string[] text) {
    WriteAllText(path, text.join("\n"));
}

void WriteAllText(string path, string text) {
    write(path.replace("\\x", "%"), text);
}

string[] FindLoginProtection(string[] files) {
    string stringMsg = "pushstring          \"identification\"";
    foreach (file; files) {
        string[] lines = ReadAllLines(file);
        int x = 0;
        while (x < lines.length) {
            if (contains(lines[x],stringMsg)) {
                return [lines[x-1].split("\"")[3]];
            }
            x+=1;
        }
    }
    return [];
}

string[] FindKeyProtection(string[] files) {
    string stringMsg = "pushstring          \"msg\"";
    foreach (file; files) {
        string[] lines = ReadAllLines(file);
        for (size_t x = 0; x < lines.length; x++) {
            if (contains(lines[x],stringMsg)) {
                return [lines[x-1].split("\"")[3]];
            }
        }
    }
    return [];
}

string[] FindFile(string[] a, string[] files) {
    string find = "getproperty         QName(PackageNamespace(\"\"), \""~a[0]~"\")";
    foreach (file; files) {
        string[] lines = ReadAllLines(file);
        for (size_t x = 0; x < lines.length; x++) {
            if (contains(lines[x],find)) {
                return [GetClassNameByFile(file), lines[x]];
            }
        }
    }
    return [];
}

void DesprotectLogin(string[] a) {
	string path = GetPathByName(a[0]);
    string[] lines = ReadAllLines(GetPathByName(a[0]));
    string[] find = ["iftrue", "iffalse"];
    foreach (size_t x, ref line; lines) {
        if (contains(line,find[0])) {
            line = line.replaceFirst(find[0]~"  ", find[1]);
        } else if (contains(line,find[1])) {
            line = line.replaceFirst(find[1], find[0]);
            WriteAllLines(path, lines);
            return;
        }
    }
}

void DesprotectPackets(string[] a)
{
    string path = GetPathByName(a[0]);
    string[] lines = ReadAllLines(GetPathByName(a[0]));
    int x = 0;
    string temp = "SpaceRemoveXD11";
    while (x < lines.length)
    {
        if (contains(lines[x],a[1]))
        {
            x += 5;
            while (!contains(lines[x],"returnvoid"))
            {
                lines[x] = temp;
				lines.remove(temp);
                x++;
            }
            WriteAllLines(path, lines);
            return;
        }
        x++;
    }
}

void main()
{
	writeln("Started");
    string[] files = GetAllAsasm();
    string[] P1 = FindKeyProtection(files);
	if (P1) {
		string[] P2 = FindFile(P1, files);
		if (P2) {
		    string[] P3 = FindLoginProtection(files);
            if (P3) {
				string[] P4 = FindFile(P3, files);
				if (P4) {
					DesprotectLogin(P4);
                    DesprotectPackets(P2);
                    writeln("Finished");
				}
			}
		}
	}
}