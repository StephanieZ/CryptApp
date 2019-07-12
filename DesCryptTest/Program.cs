using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Xml.Schema;
using CryptSharp;

namespace CryptApp
{
  public class Program
  {
    static DesCrypt cCrypt = new DesCrypt();
    const string salt = "..";
    public static int maxLength = 4;
    public static int count = 0;
    private static object jsLock = new object(); 


    static void Main(string[] args)
    {

      // maximum security AIX required a minimum of 4 chars in passwords, DES limits total password length to 8 chars

      // for all 4 char strings
      CompareAllPasswords("", 0);

      // for all 5 char strings
      maxLength = 5;
      CompareAllPasswords("", 0);

      // for all 6 char strings
      maxLength = 6;
      CompareAllPasswords("", 0);

      // for all 7 char strings
      maxLength = 7;
      CompareAllPasswords("", 0);

      // for all 8 char strings
      maxLength = 8;
      CompareAllPasswords("", 0);

    }
  








    public static void CompareAllPasswords(string password, int length)
    {
        length += 1;

      foreach (var c in DesCrypt.Ascii64)
      {
        count++;
        if (length == maxLength &&
            length == (password + c).Length &&
            count >= Math.Pow(10, maxLength))
        {
          try
          {
            count = 0;
            Task.Run(() => ComparePassword(password + c));
          }
          catch
          {
            //if we fail to start some passwords, no biggie, just skip them until memory is availble again.
          }

        }

        if (length < maxLength)
        {
          CompareAllPasswords(password + c, length);
        }
      }
    }

    private static void ComparePassword(string password)
    {
      
      string outputFile = "passwordComparison.log";

      //as it turns out, the standard out isn't threadsafe.
      lock (jsLock)
      {
        var cCryptString = cCrypt.Descrypt(password, salt);

        var oldCheckPassword = Crypter.CheckPassword(password, cCryptString);

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


        File.AppendAllText(outputFile, password + '\n');
        File.AppendAllText(outputFile, jCryptString + '\n');
        File.AppendAllText(outputFile, cCryptString + '\n');
        if (string.CompareOrdinal(jCryptString, cCryptString) == 0)
        {
          File.AppendAllText(outputFile, "A password check succeeded\n");
          if (!oldCheckPassword)
          {
            File.AppendAllText(outputFile, "The only algorithm would have failed");
          }
        }
        else
        {
          File.AppendAllText(outputFile, "A password check failed\n");
        }


      }

    }
  }
}

 
