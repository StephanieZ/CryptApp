using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptApp
{
  internal class Program
    {
        static void Main(string[] args)
        {
            var crypter = new DesCrypt();

            Console.WriteLine(crypter.ComparePasswordHash("Test123", "..sO6U/h2bd8I", "..")
                ? "Winner Winner"
                : "Keeeeep workin");

            Console.ReadLine();
        }
    }
}
