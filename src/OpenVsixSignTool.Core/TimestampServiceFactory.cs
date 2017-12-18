using System;
using System.Runtime.InteropServices;

namespace OpenVsixSignTool.Core
{
    public static class TimestampServiceFactory
    {
        public static ITimestampService GetTimestampService()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return new Windows.WindowsTimestampService();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return new MacOS.MacOSTimestampService();
            }
            else
            {
                throw new PlatformNotSupportedException();
            }
        }
    }
}