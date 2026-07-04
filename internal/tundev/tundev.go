// Package tundev wraps golang.zx2c4.com/wireguard/tun with the buffer
// layout from pktbuf and a mutex-serialized writer.
package tundev

import (
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// Device is an open TUN device.
type Device struct {
	dev  tun.Device
	name string

	writeMu sync.Mutex
}

// Open creates the TUN device. On macOS pass "utun" to let the kernel
// pick a number.
func Open(name string, mtu int) (*Device, error) {
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, err
	}
	realName, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, err
	}
	return &Device{dev: dev, name: realName}, nil
}

// Name returns the actual interface name (e.g. utun4 on macOS).
func (d *Device) Name() string { return d.name }

// BatchSize returns the device's preferred batch size.
func (d *Device) BatchSize() int { return d.dev.BatchSize() }

// Read reads up to len(bufs) packets; each lands at bufs[i][offset:].
// It blocks until at least one packet is available.
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return d.dev.Read(bufs, sizes, offset)
}

// Write writes packets located at bufs[i][offset:]. The device requires
// headroom before offset (virtio/utun prefixes); pktbuf's layout provides
// it. Serialized internally: safe from multiple goroutines.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return d.dev.Write(bufs, offset)
}

// Close shuts the device down, unblocking readers.
func (d *Device) Close() error { return d.dev.Close() }
