using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertAuthorityInfo
{
    internal static class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!{0}", Environment.NewLine);

            if (args.Length < 1)
            {
                Console.WriteLine("Usage: CertAuthorityInfo <filename>.{0}", Environment.NewLine);
                Console.Read();
                return;
            }

            WriteCertInfo(args[0]);
            Console.Read();
        }

        // https://docs.microsoft.com/en-us/azure-stack/asdk/asdk-cli?view=azs-2102&tabs=win
        private static void WriteCertInfo(string certPath)
        {
            try
            {
                //Create X509Certificate2 object from .pem file.
                X509Certificate2 x509 = new X509Certificate2(certPath);
                //x509.Import(data.Item1);

                //Print to console information contained in the certificate.
                Console.WriteLine("Issuer: {1}{0}", Environment.NewLine, x509.Issuer);
                Console.WriteLine("Subject: {1}{0}", Environment.NewLine, x509.Subject);
                Console.WriteLine("Serial Number: {1}{0}", Environment.NewLine, x509.SerialNumber);
                Console.WriteLine("Certificate to string: {1}{0}", Environment.NewLine, x509.ToString(true));

                Console.WriteLine("{0}Add to Store?{0}", Environment.NewLine);
                var shouldAddToStore = Console.ReadKey().Key;
                if (shouldAddToStore.Equals(ConsoleKey.Y))
                {
                    AddToStore(x509);
                }

                Console.WriteLine("{0}Append to an existing file?{0}", Environment.NewLine);
                var shouldAppendToFile = Console.ReadKey().Key;
                if (shouldAppendToFile.Equals(ConsoleKey.Y))
                {
                    Console.WriteLine("{0}Which file <C:\\Users\\File.pem>?{0}", Environment.NewLine);
                    var pathToFile = Console.ReadLine();
                    AppendToFile(x509.RawData, pathToFile);
                }
            }
            catch (DirectoryNotFoundException)
            {
                Console.WriteLine("Error: The directory specified could not be found.");
            }
            catch (IOException)
            {
                Console.WriteLine("Error: A file in the directory could not be accessed.");
            }
            catch (NullReferenceException)
            {
                Console.WriteLine("File must be a .pem file. Program does not have access to that type of file.");
            }
            catch (Exception)
            {
                Console.WriteLine("Error: an unhandled exception happened.");
            }
        }

        private static void AppendToFile(byte[] buffer, string pathToFile)
        {
            var md5Hash = GetFileHash("MD5", buffer);
            var sha1Hash = GetFileHash("SHA1", buffer);
            var sha256Hash = GetFileHash("SHA256", buffer);

            Console.WriteLine("{0}{1}: {2}{0}", Environment.NewLine, nameof(md5Hash), md5Hash);
            Console.WriteLine("{0}{1}: {2}{0}", Environment.NewLine, nameof(sha1Hash), sha1Hash);
            Console.WriteLine("{0}{1}: {2}{0}", Environment.NewLine, nameof(sha256Hash), sha256Hash);

            Console.WriteLine("{0}Appending the certificate content to file.{0}", Environment.NewLine);
            File.AppendAllLines(pathToFile, new string[] { md5Hash, sha1Hash, sha256Hash });

            static string GetFileHash(string hashname, byte[] buffer)
            {
                using (var hashAlgorithm = HashAlgorithm.Create(hashname))
                {
                    var hash = hashAlgorithm.ComputeHash(buffer);
                    return BitConverter.ToString(hash);
                }
            }
        }

        private static void AddToStore(X509Certificate2 x509)
        {
            //Add the certificate to a X509Store.
            //X509Store store = new X509Store();
            //store.Open(OpenFlags.MaxAllowed);
            //store.Add(x509);
            //store.Close();
            Console.WriteLine("{0}Added the certificate to a X509Store.{0}", Environment.NewLine);
        }
    }
}
