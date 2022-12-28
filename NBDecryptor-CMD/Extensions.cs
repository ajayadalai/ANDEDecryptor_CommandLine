using System;
using SystemX509 = System.Security.Cryptography.X509Certificates;

namespace NBDecryptor_CMD
{
    public static class Extensions
    {
        private static Action doNothing = delegate() { };

        //public static void Refresh(this UIElement uiElement)
        //{
        //    uiElement.Dispatcher.Invoke(DispatcherPriority.Input, doNothing);
        //}

        /*
        public static string ToReadableString(this DataType ty)
        {
            switch (ty)
            {
                case (DataType.Run):
                case (DataType.Optical):
                case (DataType.Telemetry):
                case (DataType.Usage):
                    return ty.ToString();
                case (DataType.RunReport):
                    return "Run Report";
                default:
                    return "?";
            }
        }*/

        public static string BaseName(this SystemX509.X509Certificate2 cert)
        {
            return cert.SubjectName.Name.Replace("CN=", "");
        }

        public static string InstrumentSerialNum(this SystemX509.X509Certificate2 cert)
        {
            string base_name = cert.BaseName();

            if (base_name.StartsWith("i") && base_name.Length >= 5)
            {
                return base_name.Substring(1, 4);
            }
            return "???";
        }
    }
}
