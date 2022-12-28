using Ionic.Zip;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;


namespace NBDecryptor_CMD
{
    class Program
    {
        const string certName = @"PX_Service_20130402_160247.pfx";
        const string certPwd = "12345678";
        static void Main(string[] args)
        {
            string certificateName = string.Empty;
            AppDomain.CurrentDomain.AssemblyResolve += (sender, arguements) =>
            {
                Assembly thisAssembly = Assembly.GetExecutingAssembly();

                //Installing certificate from Resources
                if (!IsCertificateInstalled("CN=" + Path.GetFileNameWithoutExtension(certName)))
                {
                    Console.WriteLine("Installing Certificate....");
                    // var cername = "PX_Service_20130402_160247.pfx";//arguements.Name.Substring(0, arguements.Name.IndexOf(',')) + ".pfx";
                    var cerres = thisAssembly.GetManifestResourceNames().Where(s => s.EndsWith(certName));
                    var cerresourceName = cerres.First();
                    //Console.WriteLine(cerresourceName);
                    //Console.WriteLine(Path.GetFileNameWithoutExtension(certName));
                    using (Stream cs = thisAssembly.GetManifestResourceStream(cerresourceName))
                    {
                        Byte[] raw = new Byte[cs.Length];
                        for (Int32 i = 0; i < cs.Length; ++i)
                            raw[i] = (Byte)cs.ReadByte();
                        Console.WriteLine(CertHelper.ImportCertificateWithPrivateKey(raw, certPwd));
                        Console.WriteLine(String.Format("Installed Certificate {0}", certName));
                    }
                }
                Console.WriteLine(String.Format("Certificate used for decryption {0}", certName));


                //Loading dll from Resources
                var name = arguements.Name.Substring(0, arguements.Name.IndexOf(',')) + ".dll";

                var resources = thisAssembly.GetManifestResourceNames().Where(s => s.EndsWith(name));
                if (resources.Count() > 0)
                {
                    var resourceName = resources.First();
                    using (Stream stream = thisAssembly.GetManifestResourceStream(resourceName))
                    {
                        if (stream == null) return null;
                        var block = new byte[stream.Length];
                        stream.Read(block, 0, block.Length);
                        return Assembly.Load(block);
                    }
                }
                return null;
            };



            if (args.Length == 0)
            {
                Console.WriteLine("Please enter Zip File Path");
            }
            else
            {
                Console.WriteLine("Decrypting....");
                FileDecrypter.DecryptFile(args[0].ToString(), "PX_Service_20130402_160247");
            }
        }



        static bool IsCertificateInstalled(string certName)
        {
            var all_certs = CertHelper.GetCertificatesLike("(i[0-9][0-9][0-9][0-9]_[0-9]+_[0-9]+$)|(^PX_)|(^RDNA_)");
            foreach (var cert in all_certs)
            {
                if (cert.Subject == certName)
                    return true;
            }
            return false;
        }


    }
}




//private void EncryptExportedData(string path, string cert)
//{
//    //if (certs_.Items.Count == 0 || signCerts_.Items.Count == 0)
//    //{
//    //    return;
//    //}

//    //string cert = certs_.SelectedItem as string;

//    string from_path = path.Trim();
//    if (string.IsNullOrEmpty(from_path))
//    {
//        Console.WriteLine("Enter path to (or drag) .zip archive.");
//        return;
//    }
//    if (!File.Exists(from_path))
//    {
//        Console.WriteLine("Specified path does not exist.");
//        return;
//    }

//    try
//    {
//        //Mouse.OverrideCursor = Cursors.Wait;
//        //Console.WriteLine("Encrypting...");

//        string to_path = from_path.Replace("_decrypted.zip", ".zip");
//        if (File.Exists(to_path))
//        {
//            throw new ApplicationException(string.Format("{0} already exists.", to_path));
//        }

//        string sign_cert = signCerts_.SelectedItem as string;

//        using (var crypto = new Crypto(cert, sign_cert))
//        {
//            if (!crypto.Valid)
//            {
//                Console.WriteLine(string.Format("No key for {0}.cer", cert));
//                return;
//            }

//            using (ZipFile enc = new ZipFile())
//            {
//                using (ZipFile dec = ZipFile.Read(from_path))
//                {
//                    foreach (ZipEntry dec_entry in dec)
//                    {
//                        MemoryStream buffer = new MemoryStream();
//                        dec_entry.Extract(buffer);
//                        buffer.Seek(0, 0);

//                        buffer = crypto.Sign(buffer);
//                        buffer = crypto.Encrypt(buffer);
//                        buffer = crypto.Sign(buffer);

//                        // Avoid .Replace() - be sure that we only remove from the end
//                        string enc_filename = dec_entry.FileName + ".enc";

//                        enc.AddEntry(enc_filename, buffer.ToArray());
//                    }
//                }

//                enc.Save(to_path);
//            }
//        }

//      //  ClearConsole.WriteLine();
//    }
//    finally
//    {
//      //  Mouse.OverrideCursor = null;
//    }
//}
