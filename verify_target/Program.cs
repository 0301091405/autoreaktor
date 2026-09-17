// Test target for AutoReaktor verification: a plain .NET 8 console app
// with string encryption-relevant content. Build: dotnet publish -c Release
using System;

class Program
{
    const string SECRET_1 = "DH-VERIFY-PLAINTEXT-MARKER-7F3A";
    static readonly string SECRET_2 = "DH-VERIFY-SECRET-" + Guid.NewGuid().ToString("N").Substring(0, 8).ToUpper();

    static int Main(string[] args)
    {
        Console.WriteLine("hello from test target");
        if (args.Length > 0 && args[0] == "dump")
        {
            Console.WriteLine(SECRET_1);
            Console.WriteLine(SECRET_2);
        }
        // small logic so the assembly has real IL beyond strings
        int acc = 0;
        for (int i = 0; i < 10; i++) acc += i * 3;
        return acc == 135 ? 0 : 1;
    }
}
