using Ionic.Zip;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;


namespace NBDecryptor_CMD
{
    public static class FileDecrypter
    {
        private static bool decryptMode_ = true;

        private static bool IsRecoveryFile(string path)
        {
            return System.IO.Path.GetFileName(path).ToLower().EndsWith("recovery.txt");
        }

        public static void DecryptFile(string path, string cert)
        {
            try
            {
                //string path = inputPath_.Text.Trim();
                if (string.IsNullOrEmpty(path.Trim()))
                {
                    return;
                }

                if (decryptMode_)
                {
                    if (IsRecoveryFile(path))
                    {
                        DecryptRecovery(path, cert);
                    }
                    else
                    {
                        DecryptExportedData(path, cert);
                    }
                }
                else
                {
                    //EncryptExportedData();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("Problem decrypting: {0}", ex.Message));
            }
        }

        private static void DecryptExportedData(string path, string cert)
        {
            string output = string.Empty;
            string from_path = path.Trim();
            if (string.IsNullOrEmpty(from_path))
            {
                Console.WriteLine("Enter path to (or drag) .zip archive.");
                return;
            }
            //if (!File.Exists(from_path))
            //{
            //    Console.WriteLine("Specified path does not exist.");
            //    return;
            //}

            try
            {

                if (File.Exists(from_path))
                {
                    output = FileDecrypter.Decrypt(from_path, cert);
                    Console.WriteLine(output);
                }
                else
                {
                    string[] files = Directory.GetFiles(from_path, "*.zip", SearchOption.AllDirectories);

                    foreach (var filePath in files)
                    {
                        output += FileDecrypter.Decrypt(filePath, cert);
                    }
                    Console.WriteLine(output);
                }

                //string to_path = System.IO.Path.Combine(
                //                        System.IO.Path.GetDirectoryName(from_path)
                //                      , System.IO.Path.GetFileNameWithoutExtension(from_path) + "_decrypted.zip");

                //using (var crypto = new Crypto(cert))
                //{
                //    if (!crypto.Valid)
                //    {
                //        Console.WriteLine(string.Format("No key for {0}.cer", cert));
                //        return;
                //    }

                //    using (ZipFile dec = new ZipFile())
                //    {
                //        List<string> rejFiles = new List<string>();
                //        using (ZipFile enc = ZipFile.Read(from_path))
                //        {
                //            if (!enc.Entries.Any(x => x.FileName.Contains(".enc")))
                //            {
                //                Console.WriteLine("Error: The folder doesn't contain any encrypted file.");
                //                return;
                //            }
                //            foreach (ZipEntry enc_entry in enc)
                //            {
                //                try
                //                {
                //                MemoryStream buffer = new MemoryStream();
                //                enc_entry.Extract(buffer);
                //                buffer.Seek(0, 0);

                //                buffer = crypto.CheckSignatureAndExtract(buffer);
                //                buffer = crypto.Decrypt(buffer);
                //                buffer = crypto.CheckSignatureAndExtract(buffer);

                //                // Avoid .Replace() - be sure that we only remove from the end
                //                string dec_filename = enc_entry.FileName;
                //                if (dec_filename.ToLower().EndsWith(".enc"))
                //                {
                //                    dec_filename = dec_filename.Substring(0, dec_filename.Length - 4);
                //                }

                //                dec.AddEntry(dec_filename, buffer.ToArray());

                //                }
                //                catch (Exception)
                //                {
                //                    rejFiles.Add(enc_entry.FileName);
                //                    continue;
                //                }
                //            }
                //        }

                //        dec.Save(to_path);
                //        string failedFiles = string.Format("Unable to decrypt the following files: {0}", string.Join(", ", rejFiles.ToArray()));
                //        if (rejFiles.Count() > 0)
                //            Console.WriteLine(string.Format("{0} files decrypted successfully.\n{1}", dec.Count(), failedFiles));
                //        else
                //            Console.WriteLine(string.Format("{0} files decrypted successfully.", dec.Count()));

                //    }
                //}

            }
            finally
            {

            }
        }

        private static void DecryptRecovery(string path, string cert)
        {
            string rec_file = path.Trim();

            string[] lines = File.ReadAllLines(rec_file);
            if (lines.Length < 2)
            {
                Console.WriteLine("Recovery.txt file not in expected format");
                return;
            }

            try
            {
                string tmp_pw = "";
                Console.WriteLine("Decrypting...");

                string enc = lines[1].Trim();
                byte[] enc_bytes = Convert.FromBase64String(enc);
                using (var crypto = new Crypto(cert))
                {
                    byte[] clear = crypto.RSADecrypt(enc_bytes);
                    tmp_pw = new string(Encoding.ASCII.GetChars(clear));
                }

            }
            finally
            {
            }
        }

        private static string Decrypt(string from_path, string cert)
        {
            List<string> msgOutput = new List<string>();
            string to_path = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(from_path), System.IO.Path.GetFileNameWithoutExtension(from_path) + "_decrypted.zip");
            string fileName = Path.GetFileName(from_path);
            using (var crypto = new Crypto(cert))
            {
                if (!crypto.Valid)
                {
                    return string.Format("No key for {0}.cer", cert);
                }

                using (ZipFile dec = new ZipFile())
                {
                    List<string> rejFiles = new List<string>();

                    using (ZipFile enc = ZipFile.Read(from_path))
                    {
                        if (!enc.Entries.Any(x => x.FileName.Contains(".enc")))
                        {
                            return("The folder doesn't contain any encrypted file.");
                           
                        }
                        foreach (ZipEntry enc_entry in enc)
                        {
                            try
                            {
                                MemoryStream buffer = new MemoryStream();
                                enc_entry.Extract(buffer);
                                buffer.Seek(0, 0);

                                buffer = crypto.CheckSignatureAndExtract(buffer);
                                buffer = crypto.Decrypt(buffer);
                                buffer = crypto.CheckSignatureAndExtract(buffer);

                                // Avoid .Replace() - be sure that we only remove from the end
                                string dec_filename = enc_entry.FileName;
                                if (dec_filename.ToLower().EndsWith(".enc"))
                                {
                                    dec_filename = dec_filename.Substring(0, dec_filename.Length - 4);
                                }
                                dec.AddEntry(dec_filename, buffer.ToArray());

                            }
                            catch (Exception)
                            {
                                rejFiles.Add(enc_entry.FileName);
                                continue;
                            }
                        }
                    }

                    dec.Save(to_path);
                    //return "File decrypted successfully.";
                    //string failedFiles = string.Format("Unable to decrypt the following files: {0}", string.Join(", ", rejFiles.ToArray()));
                    //if (rejFiles.Count() > 0)
                    //    Message.Display("Information", string.Format("\n{0} files decrypted successfully.\n{1}", dec.Count(), failedFiles));
                    //else
                    //    Message.Display("Information", string.Format("\n{0} files decrypted successfully.", dec.Count()));

                    string failedFiles = string.Format("\nUnable to decrypt the following files: {0}\n", string.Join(", ", rejFiles.ToArray()));
                    if (rejFiles.Count() > 0)
                        msgOutput.Add(string.Format("\n{0}\n{1} files decrypted successfully.\n{2}", fileName, dec.Count(), failedFiles));
                    //Message.Display("Information", string.Format("\n{0} files decrypted successfully.\n{1}", dec.Count(), failedFiles));
                    else
                        msgOutput.Add(string.Format("\n{0}\n{1} files decrypted successfully.\n", fileName, dec.Count()));
                    //Message.Display("Information", string.Format("\n{0} files decrypted successfully.", dec.Count()));
                }
            }
            return string.Join("\n", msgOutput.ToArray());
        }
    }
}
