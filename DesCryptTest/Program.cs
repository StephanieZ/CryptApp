using System;
using System.Diagnostics;
using System.Linq;

namespace CryptApp
{
  public class Program
  {
    static DesCrypt cCrypt = new DesCrypt();
    const string salt = "..";
    private const int maxLength = 4;

    static void Main(string[] args)
    {
      
      CompareAllPasswords("", 0);
      Debugger.Break();
    }
  


// maximum security AIX required a minimum of 4 chars in passwords, DES limits total password length to 8 chars

// for all 4 char strings


// for all 5 char strings
// for all 6 char strings
// for all 7 char strings
// for all 8 char strings





    public static void CompareAllPasswords(string password, int length)
    {
    
        length += 1;
        foreach (var c in DesCrypt.Ascii64)
        {
          if(length == maxLength && length == (password+c).Length)
            ComparePassword(password+c);
          if (length < maxLength)
          {
            CompareAllPasswords(password + c, length);
          }
        }
      
    }

    private static void ComparePassword(string password)
    {
      var cCryptString = cCrypt.Descrypt(password, salt);

      var jCompareProcess = new Process
      {
        StartInfo = new ProcessStartInfo
        {
          FileName = "node",
          Arguments = $"..\\..\\app.js {password} {salt}",
          UseShellExecute = false,
          RedirectStandardOutput = true,
          CreateNoWindow = true
        }
      };

      jCompareProcess?.Start();

      jCompareProcess?.WaitForExit();

      var jCryptString = jCompareProcess.StandardOutput.ReadLine();

      if (string.CompareOrdinal(jCryptString, cCryptString) != 0)
      {
        Console.WriteLine(password);
        Console.WriteLine(jCryptString);
        Console.WriteLine(cCryptString);
        Console.WriteLine("A password check failed");
        Debugger.Break();
      }
    }
  }
}

 
