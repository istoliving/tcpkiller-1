package tcpkiller

import (
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// TCPKiller ...
type TCPKiller struct {
	handle *pcap.Handle
	tokill sync.Map
}

// NewTCPKiller ...
func NewTCPKiller() *TCPKiller {
	return &TCPKiller{}
}

// StartSniff ...
func (k *TCPKiller) StartSniff(device string, snaplen int32, promisc bool, timeout time.Duration) error {
	handle, err := pcap.OpenLive(device, snaplen, promisc, timeout)
	if err != nil {
		return err
	}
	k.handle = handle
	k.tokill = sync.Map{}
	go k.sniff()
	return nil
}

// Kill ...
// Note: add is the address of the remote machine.
func (k *TCPKiller) Kill(addr net.Addr) {
	ch := make(chan int)
	k.tokill.Store(addr.String(), ch)
	<-ch
}

func (k *TCPKiller) kill(srcmac, dstmac net.HardwareAddr, srcip, dstip net.IP, srcport, dstport layers.TCPPort, seq uint32, ack uint32, ch chan int) {
	tcp := &layers.TCP{
		Seq:     seq,
		Ack:     ack,
		SrcPort: srcport,
		DstPort: dstport,
		Window:  0,
		ACK:     true,
		RST:     true}
	ip := &layers.IPv4{
		Version:    4,
		IHL:        5,
		Id:         0,
		Flags:      0,
		FragOffset: 0,
		TTL:        255,
		Protocol:   6,
		SrcIP:      srcip,
		DstIP:      dstip}
	mac := &layers.Ethernet{
		SrcMAC:       srcmac,
		DstMAC:       dstmac,
		EthernetType: 0x800}
	k.send_tcp([]byte{}, tcp, ip, mac)
	ch <- 1
}

func (k *TCPKiller) sniff() {
	packetSource := gopacket.NewPacketSource(k.handle, k.handle.LinkType())
	for packet := range packetSource.Packets() {
		if tcplayer := packet.Layer(layers.LayerTypeTCP); tcplayer != nil {
			tcp, _ := tcplayer.(*layers.TCP)
			iplayer := packet.Layer(layers.LayerTypeIPv4)
			ip, _ := iplayer.(*layers.IPv4)
			maclayer := packet.Layer(layers.LayerTypeEthernet)
			mac, _ := maclayer.(*layers.Ethernet)
			src := net.TCPAddr{
				IP:   ip.SrcIP,
				Port: int(tcp.SrcPort)}
			dst := net.TCPAddr{
				IP:   ip.DstIP,
				Port: int(tcp.DstPort)}
			srcmac := mac.SrcMAC
			dstmac := mac.DstMAC
			srcip := ip.SrcIP
			dstip := ip.DstIP
			srcport := tcp.SrcPort
			dstport := tcp.DstPort
			if chv, ok := k.tokill.Load(src.String()); ok {
				// dst is our machine.
				ch := chv.(chan int)
				go k.kill(dstmac, srcmac, dstip, srcip, dstport, srcport, tcp.Ack+uint32(1), tcp.Seq+uint32(len(tcp.Payload)), ch)
			}
			if chv, ok := k.tokill.Load(dst.String()); ok {
				// src is our machine
				ch := chv.(chan int)
				go k.kill(srcmac, dstmac, srcip, dstip, srcport, dstport, tcp.Seq+uint32(len(tcp.Payload))+uint32(1), tcp.Ack, ch)
				go k.kill(srcmac, dstmac, srcip, dstip, srcport, dstport, tcp.Seq+uint32(1), tcp.Ack, ch)
			}
		}
	}
}

// modified from https://github.com/ebiken/go-sendpacket
func (k *TCPKiller) send_tcp(data []byte,
	tcpLayer *layers.TCP,
	ipv4Layer *layers.IPv4,
	ethernetLayer *layers.Ethernet) (err error) {

	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true},
		tcpLayer,
		gopacket.Payload(data),
	)
	return k.send_ipv4(buffer.Bytes(), ipv4Layer, ethernetLayer)
}

func (k *TCPKiller) send_ipv4(data []byte,
	ipv4Layer *layers.IPv4,
	ethernetLayer *layers.Ethernet) (err error) {

	buffer_ipv4 := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer_ipv4, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true},
		ipv4Layer,
		gopacket.Payload(data),
	)
	return k.send_ethernet(buffer_ipv4.Bytes(), ethernetLayer)
}

func (k *TCPKiller) send_ethernet(data []byte,
	ethernetLayer *layers.Ethernet) (err error) {

	buffer_ethernet := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer_ethernet, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true},
		ethernetLayer,
		gopacket.Payload(data),
	)
	err = k.handle.WritePacketData(buffer_ethernet.Bytes())
	return err
}
