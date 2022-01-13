using System.Net;
using System.Net.NetworkInformation;
using SharpPcap;
using PacketDotNet;
using PacketDotNet.Utils;

namespace ARPsniffer
{
    public class Program
    {
        private static Dictionary<string, string> ouiOrgDict = new Dictionary<string, string>();

        public static async Task Main()
        {
            var exeFilePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
            var exeFolderPath = Path.GetDirectoryName(exeFilePath);
            if (exeFolderPath == null)
            {
                Console.WriteLine("Can't get file location. Probably not enough rights");
                return;
            }
            var ouiFilePath = Path.Combine(exeFolderPath, "oui.txt");
            if (!File.Exists(ouiFilePath))
            {
                Console.Write("Downloading oui.txt...");
                var t = DownloadOUIFileAsync(ouiFilePath);
                try
                {
                    await t;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("\n{0}", ex.Message);
                    return;
                }
                Console.WriteLine("Complete");
            }

            FilterOUIFile(File.ReadLines(ouiFilePath), ouiOrgDict);
            
            var devices = CaptureDeviceList.Instance;

            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return;
            }

            Console.WriteLine("The following devices are available on this machine:\n");

            int i = 0;

            foreach (var dev in devices)
            {
                Console.WriteLine("{0}) {1} ({2}), {3}", i, dev.Description,
                    dev.MacAddress != null ? HexPrinter.PrintMACAddress(dev.MacAddress) : "<null>", 
                    GetOrgFromMacAddress(dev.MacAddress, ouiOrgDict));
                i++;
            }

            Console.WriteLine();
            Console.Write("Please choose a device to capture: ");
            if (int.TryParse(Console.ReadLine(), out int val))
            {
                if (val < 0 || val >= i)
                {
                    Console.WriteLine("Wrong number");
                    return;
                }
            }
            else
            {
                Console.WriteLine("Not a number");
                return;
            }
            
            var device = devices[val];

            device.OnPacketArrival += new PacketArrivalEventHandler(Device_OnPacketArrival);
            try
            {
                device.Open(DeviceModes.Promiscuous, 1000);
                device.Filter = "arp";
            }
            catch (Exception ex)
            {
                Console.WriteLine("\n{0}", ex.Message);
                return;
            }

            Console.WriteLine();
            Console.WriteLine("Listening on {0}, hit 'Ctrl-C' to exit...", device.Description);

            device.Capture();
        }

        private static void Device_OnPacketArrival(object sender, PacketCapture e)
        {
            var rawPacket = e.GetPacket();

            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            var arpPacket = packet.Extract<ArpPacket>();
            var ethFrame = packet.Extract<EthernetPacket>();

            if (arpPacket != null)
            {
                var srcHWAddress = arpPacket.SenderHardwareAddress;
                var dstHWAddress = arpPacket.TargetHardwareAddress;
                var opcode = arpPacket.Operation;
                string spec = "";
                
                if (arpPacket.SenderProtocolAddress.Equals(arpPacket.TargetProtocolAddress) &&
                    GetOrgFromMacAddress(ethFrame.DestinationHardwareAddress, ouiOrgDict).Equals("<broadcast>"))
                {
                    if (opcode == ArpOperation.Request)
                    {
                        spec += "[Announcement]";
                    }
                    spec += "[Gratuitous]";
                }
                if (opcode == ArpOperation.Request && arpPacket.SenderProtocolAddress.Equals(IPAddress.Parse("0.0.0.0")))
                {
                    spec += "[Probe]";
                }
                Console.WriteLine("\n{0:HH:mm:ss,fffff} [{1}]\t{2} -> {3} {4}\n{5} -> {6}", e.Header.Timeval.Date, opcode,
                    HexPrinter.PrintMACAddress(srcHWAddress), HexPrinter.PrintMACAddress(dstHWAddress), spec,
                    GetOrgFromMacAddress(srcHWAddress, ouiOrgDict).PadLeft(49, ' '), GetOrgFromMacAddress(dstHWAddress, ouiOrgDict));
            }
        }

        private static string GetOrgFromMacAddress(PhysicalAddress? addr, Dictionary<string, string> dict)
        {
            if (addr == null)
            {
                return "<null>";
            }
            else if (addr.ToString() == string.Join("", Enumerable.Repeat('0', 12)))
            {
                return "<empty>";
            }
            else if (addr.ToString() == string.Join("", Enumerable.Repeat('F', 12)))
            {
                return "<broadcast>";
            }
            else if (dict.TryGetValue(addr.ToString()[..6], out var org))
            {
                return org;
            }
            else
            {
                return "<Unknown_Vendor>";
            }
        }

        private static void FilterOUIFile(IEnumerable<string> ss, Dictionary<string, string> dict)
        {
            foreach (string s in ss)
            {
                if (s.Contains("     (base 16)		"))
                {
                    var OUI = s.Split(' ')[0];
                    var Organization = s.Split("\t\t")[1];
                    if (dict.ContainsKey(OUI))
                    {
                        dict[OUI] = dict[OUI] + ", also " + Organization;
                    }
                    else
                    {
                        dict.Add(s.Split(' ')[0], s.Split("\t\t")[1]);
                    }
                }     
            }
        }
        
        private static async Task DownloadOUIFileAsync(string ouiFilePath)
        {
            var httpClient = new HttpClient();
            using (var stream = await httpClient.GetStreamAsync("http://standards-oui.ieee.org/oui/oui.txt"))
            {
                using (var fileStream = new FileStream(ouiFilePath, FileMode.CreateNew))
                {
                    await stream.CopyToAsync(fileStream);
                }
            }
        }
    }
}