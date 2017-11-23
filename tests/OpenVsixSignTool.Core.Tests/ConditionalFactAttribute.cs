using System.Runtime.InteropServices;
using Xunit;

namespace OpenVsixSignTool.Core.Tests
{
    public sealed class ConditionalTheoryAttribute : TheoryAttribute
    {
        public ConditionalTheoryAttribute(bool supportsWindows = false, bool supportsMacOS = false, bool supportsLinux = false)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && !supportsWindows)
            {
                Skip = "Windows does not support this unit test.";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX) && !supportsMacOS)
            {
                Skip = "MacOS does not support this unit test.";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) && !supportsLinux)
            {
                Skip = "Linux does not support this unit test.";
            }
        }

        public new string Skip {
            get => base.Skip;
            private set => base.Skip = value;
        }
    }

    public sealed class ConditionalFactAttribute : FactAttribute
    {
        public ConditionalFactAttribute(bool supportsWindows = false, bool supportsMacOS = false, bool supportsLinux = false)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && !supportsWindows)
            {
                Skip = "Windows does not support this unit test.";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX) && !supportsMacOS)
            {
                Skip = "MacOS does not support this unit test.";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) && !supportsLinux)
            {
                Skip = "Linux does not support this unit test.";
            }
        }

        public new string Skip {
            get => base.Skip;
            private set => base.Skip = value;
        }
    }
}