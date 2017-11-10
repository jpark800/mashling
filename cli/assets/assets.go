// Code generated by go-bindata.
// sources:
// assets/banner.txt
// assets/default_manifest
// schema/mashling_schema-0.2.json
// DO NOT EDIT!

package assets

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _assetsBannerTxt = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x94\x95\xbd\x8e\xe4\x30\x08\xc7\xeb\xcd\x53\xd0\x31\x2b\x1f\xd0\xf3\x2c\x23\xd1\x5c\xef\xc2\xad\x1f\xfe\xf4\xf7\x47\x26\x9b\x71\x32\xb7\x24\x8a\x12\xec\x1f\x60\x0c\x0e\xed\xc2\xcc\xac\x6e\xc6\xdb\x4b\x65\x5d\xa4\xab\x14\xef\xee\xb8\xcd\x36\x22\x55\x15\x1f\x02\x25\xa6\xf9\x40\xa0\x70\x17\x31\xdd\x88\x45\xa4\x4f\x34\x53\x18\x32\xdf\x48\xfa\x34\x8c\x08\x0f\x65\x37\x37\x26\x51\x57\xd2\x47\x61\xde\xc4\x4d\x94\x99\xe9\x57\xa0\x9a\x63\xb1\xea\xc6\x47\xb5\xc9\xd1\xb8\x8f\xf0\x4e\x3e\x1d\x6b\x20\x62\x39\x04\x4b\xfc\x03\xc5\xa0\x2d\xe0\x81\xc2\xb1\xf3\x2b\x16\x79\xf3\x60\xd7\x28\xb1\x39\xb7\x2d\x63\x96\x33\xba\xb0\x86\xad\xd4\x6d\x8f\xcb\x05\x89\x17\x11\xf3\xb7\xf8\xd8\x91\x49\x55\x9d\x09\x95\xb9\xff\x67\x83\x3f\xd2\x86\xda\x49\x2f\xe9\x95\x62\x0b\x90\x52\x29\x3b\xa9\x9e\x52\x4e\x0b\x71\xe5\x15\xcb\x80\xc7\x12\x73\x32\x5b\xa1\xf0\x2e\x4b\x9a\x34\x97\xec\x88\x3d\xe7\x24\x9a\xfd\xc4\xbb\x58\xb2\xce\x2f\x71\xd2\x52\x92\x70\xca\x19\x73\x45\xce\x21\x6b\x32\x49\x77\x3c\x79\x29\xa9\xe1\xcb\x35\x63\x43\x46\xf6\xf4\xc2\x00\x59\xc9\xf9\xca\xc0\x31\xfd\x57\x11\x10\xe7\xf2\xd9\x80\xdd\x44\x80\x2c\x5c\x1b\xb0\x69\xc0\x2f\x79\xb2\x52\x96\x3c\x4e\x84\x69\xe5\x06\xe7\x95\x7f\x7b\x15\x83\xdd\xac\x7e\xec\x81\x5c\x56\x8e\x5d\xd5\xce\xee\x3b\x39\x3a\xfb\xf7\x28\xb6\x2e\x69\x6b\x15\x39\x44\xdb\x5a\xe5\x3a\xd9\xa3\xea\x66\x9f\x32\xab\xb8\x8d\x22\x45\x87\xde\x81\xd8\xea\x56\x55\xaa\xad\xa1\x75\x96\x97\xab\xe2\xf0\xb9\x63\xd1\xa6\x49\xfa\x7f\xa1\xb1\x36\x52\x8e\xde\x55\xbb\x67\xbd\x94\x7c\x3c\xbd\xfc\xef\x58\xa9\xb0\xde\xaf\xb5\x15\x57\x3a\x1c\x2c\x9c\xd4\x7a\x65\x58\xb2\x0f\x21\x53\x1e\x31\x1f\x44\xe6\x0f\x49\x94\x91\x88\x7b\x03\xd6\x9c\x63\xc9\xfd\x68\x45\xce\x54\x01\x8b\xa8\x2b\x7e\x56\x2a\x3c\xe5\xde\x16\x1b\xfc\x9d\xc5\x17\xba\x2e\x1f\x83\x9b\x7b\xd1\x2c\xc8\xca\xf8\xae\x96\x7e\x7c\xf3\xb6\x7d\x7d\x7d\x2d\x4d\xc5\x78\xc6\x59\x7f\x45\x54\xaa\xed\xf9\x88\xef\x1f\xfa\x47\x7c\x37\x24\x28\x70\xc3\x1e\x5e\xf0\x5a\xa9\x46\x00\xec\xdf\x73\xa4\x39\x8f\x68\x9e\x2a\x71\x10\x53\xd0\x93\x8c\x82\xf1\x88\xa6\x7b\xd6\xe6\x91\xf7\x91\xf6\x6d\x98\xd9\xb9\xd7\xf5\x88\x4a\xcf\xc0\xc4\x7a\xba\x1e\x2d\x84\x3a\xa2\xae\x0d\x9c\xaa\xa8\xcf\x88\x3f\x51\x23\xc2\xfa\x77\xbf\xe6\x08\x90\xf6\x16\x76\x99\xc4\xf7\xac\x86\x75\x37\xff\x35\xbb\xf9\xde\xfe\x05\x00\x00\xff\xff\x37\x0c\xc8\x3c\x83\x09\x00\x00")

func assetsBannerTxtBytes() ([]byte, error) {
	return bindataRead(
		_assetsBannerTxt,
		"assets/banner.txt",
	)
}

func assetsBannerTxt() (*asset, error) {
	bytes, err := assetsBannerTxtBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/banner.txt", size: 2435, mode: os.FileMode(436), modTime: time.Unix(1509471877, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _assetsDefault_manifest = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xd4\x9a\xcd\x72\xdb\xc8\x11\x80\xcf\xd2\x53\x6c\xe9\xbc\x32\xe6\x7f\xa6\x7d\x4c\x2e\xc9\x25\x49\xd5\xe6\x96\xca\xa1\xbb\xa7\x87\xc4\x9a\x04\x10\x00\xb4\xa5\xdd\xda\x77\x4f\x81\xb4\x2c\xca\x0b\x59\xa0\xa8\xb2\xe4\x0b\xff\xec\x1e\x7e\x5f\x0f\x31\xd3\x3d\xc2\xef\x97\x17\x57\x1f\xa5\x1f\xea\xb6\xb9\x7a\xff\x93\xfa\xf9\xf2\xe2\x2a\x4b\x27\x4d\x96\x86\x6b\x19\xae\xde\xff\xf4\x9f\xcb\x8b\x8b\xdf\x2f\x2f\x2e\x2e\xae\xea\x6d\xd7\xf6\x63\x87\xe3\xfa\xea\xfd\x4f\x57\xab\x7a\x5c\xef\xe8\x1d\xb7\xdb\xea\x1f\x6d\x96\x7f\xf5\xf5\x56\xaa\x5f\x87\xb6\xd9\xff\x87\x9f\xf7\x11\xbd\x74\xed\x50\x8f\x6d\x7f\x3b\x45\xac\xc7\xb1\x1b\xde\x57\xd5\xb2\xc8\x8f\xf5\x67\xa8\xab\xe4\x9c\xb2\x59\xb2\x77\xce\x9a\xc4\x00\x24\xd6\x45\x13\x4d\x0c\x21\xea\x08\x22\xc5\x58\x04\xfd\x39\x94\x7a\x6c\x78\x8f\xb8\xc5\x61\x94\xfe\xea\xf2\xe2\xe2\x8f\x9f\x9f\xb6\xf8\x65\xdd\x76\x75\xb9\xad\x06\xec\x71\x8b\x4b\x0d\x1e\x89\xba\xa7\xb7\x4e\x85\x64\x03\x94\x12\x6c\xd0\xa4\x8d\x01\x95\x4d\x0a\xda\x97\x62\x1d\xc6\x54\x2c\x09\x78\x7f\x2e\x7d\xdd\xef\xba\x41\x9a\x6a\xd3\xae\xfa\xdd\xb0\x18\xff\x91\xb0\xa3\xec\x43\x74\x06\xa5\xa0\x23\xa3\x42\xe6\xe2\x94\x8a\x60\x8a\xa5\x6c\x3d\x79\x67\x00\x92\x90\xa5\x33\xf9\xff\xfd\xf7\xbf\xfc\xf5\x9f\xbf\xb4\x65\xfc\x84\xbd\x54\x65\xd3\xae\xda\x6b\xde\xd4\x95\x34\x1f\x97\xba\x3c\x32\xc4\x8c\x53\xcc\x64\x9c\x28\x21\x6d\x30\x20\xd8\x94\x8a\xe3\x18\x5c\x86\x04\x3e\x3b\x65\x20\x07\x67\x74\x79\xcc\xe9\xf0\xf1\x9d\xc5\x9e\xf1\x4c\xcd\xdd\x58\x6f\xde\xbc\xe7\x1e\xf2\x1c\xd1\xb6\x19\xfb\x9a\x2a\xe4\xb1\x6e\x9b\xe9\xc3\x4f\x67\x39\x1f\x86\x9b\xf1\x86\x18\x74\x28\xce\x1a\xa7\x8c\x03\x2a\xde\x70\x36\xa4\xbd\x0e\x26\x53\x32\x4a\x93\xce\xa2\x95\x5b\xe8\x7d\xcc\xfb\x42\xfa\x1f\xeb\xf1\x76\xba\xe6\x7e\x18\xff\x2f\xc0\x2f\x99\x80\x5e\xba\xcd\xed\x8f\x95\x82\x03\xf2\xcb\x26\x61\x18\x7f\xb4\x1c\x0c\xe3\x4b\xa4\x60\xdb\x66\xd9\x54\x43\xbd\xed\x36\xf2\x43\x64\xe0\x01\xf0\x0b\x24\x60\xec\xeb\xd5\x4a\xfa\x7d\x42\x2b\x6e\xfb\xc5\xdb\xf6\xab\x66\xe1\xcf\xd4\x67\xa4\x62\x73\x44\xfc\x0c\xe9\xcd\xac\x30\x8b\x15\xab\x80\x94\xf3\xa1\x04\x4d\xd6\x9b\xe2\x02\xbb\x10\x38\x19\xa7\x2d\x79\x15\x9d\xc8\xa3\xfb\xde\xb3\x7c\xb6\x38\xac\x37\x75\xb3\xaa\xe4\x66\x3c\xd0\x7d\xc9\xd4\xaa\xed\xeb\xcd\x06\xb7\xbb\x9b\xcf\x9f\x3c\x4f\xf9\xee\x1b\x66\x8c\x7d\x34\x98\x54\x70\x3e\x24\x1b\x35\x70\x0a\xce\x17\x28\xa2\x50\x25\x31\x8c\x40\xe8\xa3\x0f\x4b\xa7\x78\x89\xc2\x79\x49\xda\xd4\x54\x71\xdb\xe4\x7a\xda\x5a\x9f\xf9\xbb\xff\x7e\xf9\xf8\x8a\xf6\x7c\xf5\xe7\xd7\x7b\xdf\x57\xfa\x94\x92\x0f\x3b\xe4\xb5\x54\xe3\xba\xaf\xcb\xb8\x8f\x9e\x7e\x3f\xfb\x77\x4b\x55\x1f\x0c\x31\x63\xe8\x4a\x8c\x48\x49\x0c\x84\x1c\x1c\xfb\x28\x41\x50\x73\x10\x5b\x54\xd1\xde\x10\xc7\x1c\xd0\xe2\x09\x86\xf7\x8c\x0b\x35\x33\x7e\x14\x5e\xad\xab\x55\x7b\x3d\x74\xf2\xa9\x9a\x1e\x96\xfa\x7d\x15\x3b\x63\x28\x9c\x05\x89\x83\x77\xe0\x73\x31\x59\x18\x7c\x8e\xec\xd0\xb1\x15\x65\x34\x28\xab\xac\x97\x47\xdb\xc5\xaf\x0c\xf7\xdf\xb2\x50\x4c\x3e\x67\x7f\xd5\x5e\xf7\x32\xd4\x9b\x5a\x1a\xbe\xad\xa8\x17\xfc\xb0\x7c\xc5\x9a\x1d\x64\xc6\x93\x74\x91\x64\xc9\x93\xb2\x25\x18\xe7\xbc\x4a\xc6\x52\xf4\x9a\x42\x30\xc6\x43\x29\x1c\xb0\x44\xb5\xd0\xf3\x8e\xf2\x74\xd5\x1b\xe9\x6b\xdc\x5c\x0f\x0d\x76\xdd\xe2\x5a\xf4\xc9\xf8\x23\x51\x02\xef\x45\x69\x02\xeb\x02\xb2\x86\xcc\x06\x84\x74\xf0\x29\x30\xa8\x2c\x19\x00\x21\xf1\x99\x7b\xd1\x1d\xd1\xff\x76\xb2\x5b\x5c\x4c\xcd\x07\x1d\x5d\x6e\x8e\x39\x29\xcf\x45\x5b\xa3\x3c\x79\x5f\x02\x88\x76\xc4\x14\x20\x85\x98\x35\x0a\x98\x02\xe9\x4c\xf6\x69\x1f\x6f\x57\x65\x3b\x56\x87\xa7\xa5\xf8\x8f\xc6\x1d\x9d\xbe\x80\x42\x8a\x60\xbd\x88\x49\xc2\x81\x4c\x0a\x36\x38\x22\x04\x72\x39\x07\xa7\x15\x93\xcd\xe7\x9e\xbe\xac\xa6\xad\xb2\xeb\xdb\xb1\xa5\x5d\xa9\xea\x76\xb9\xc1\x51\xdc\x0c\x7e\xd0\x01\x93\x91\xac\x4d\x8e\x29\x1b\x97\x5d\xb2\x60\x83\x95\x54\x2c\xfb\x6c\x8b\x51\xc1\x44\x5e\xda\xc0\xd7\xed\xf3\x84\xf6\x2f\xde\xa8\xd3\x81\x6d\xb1\xd6\x06\x9b\xd5\xb3\xc5\x1e\x04\xcf\xa8\xe9\xe0\x6c\x48\x56\x34\x79\x87\x20\x29\x61\x36\x21\x43\x2a\x49\x3b\xa5\x38\x31\x64\x28\xae\xc0\x77\x53\xe3\xeb\x95\x34\xd7\xab\xb6\xca\x32\x70\x5f\x77\x63\xbb\x78\x21\x7f\x1d\xdb\x39\xe0\xe7\x26\x60\xbc\xed\x64\x71\x65\xf9\xfd\x75\x0f\x78\x67\xc9\x55\x63\xbd\x95\x61\xc4\x6d\xf7\xc6\x35\x8f\x40\x4f\x13\x3e\x6d\x5b\x9e\x0f\x3a\x2a\x90\xbd\xc5\xe0\xb4\x8b\xca\x41\x20\x63\x4d\x44\x62\x64\xad\xc8\x06\x0b\x81\x32\x24\x71\x9e\x1f\x75\x5b\xcc\xbe\xef\x95\xaa\xed\xee\x66\x39\xf9\x9f\x43\xee\xb9\x4d\xf6\x45\x8a\x0a\x94\x40\x33\x44\x4d\xda\x21\x86\x12\x35\xa3\x47\x0a\xac\x2c\xda\x20\x4a\xce\xe4\xfe\x15\xbb\x89\xe4\x97\xfd\x85\xb7\x94\x7c\x3e\xe8\xa8\x17\x47\x24\x50\xda\x79\x52\xde\xc6\xe0\x6d\x20\x42\xb2\xd6\x58\x6d\x8a\x4b\xda\x68\x63\x45\x43\x3c\x97\x7d\x37\x95\x9a\x03\xaf\xb7\x75\x1e\xab\x89\xb3\x6f\x77\xe3\xf2\xba\xf5\xc9\xf8\xa3\x12\x5d\x13\x24\x93\x88\x41\x3c\x28\x47\x28\xac\x7c\x44\xed\x1d\x2b\x60\x74\xaa\x48\x2c\x28\x8f\x96\xae\x0b\x8d\x36\xf5\x6a\x3d\x0e\xa3\x74\xf7\xaf\xae\xc7\x1e\x59\xfa\xeb\xd5\xe2\x3d\x6b\xd9\x20\xf7\x6e\x8a\xb4\x52\x29\xeb\x04\x4a\x59\x67\xa3\x70\xc0\xa0\x5d\x49\xc8\x99\x0d\x29\x9f\x08\x45\xc5\x73\x4f\x4e\xda\x4e\x9a\x09\xa3\x6e\x56\x5f\x0e\xc3\x56\xed\x75\x4b\x83\xf4\x1f\x97\x4f\xda\xd2\x61\xee\xfd\xd0\x9b\x62\xac\x33\xce\x81\x71\x21\x7b\x62\x36\xd1\x4a\xf0\x4c\x99\x0b\xfa\x12\x73\xe0\x60\xcf\xad\xc6\x8f\xc0\x2a\xc2\xa1\xe6\x93\x27\x6e\xc1\x08\x47\x6b\x36\x59\x83\xc5\xa8\xa8\x35\xa0\x76\xa4\xc9\x58\x9d\x9d\xd7\xb9\x58\xc9\xca\x61\x34\x52\x84\x5e\x70\xd6\x1e\xa4\xfe\x79\x56\x8f\x8c\x70\x64\x65\x83\x26\xe0\x1c\x14\x49\x04\x76\x6c\x31\x16\x84\xe4\x34\x59\xd6\xd6\x88\x53\x2a\x04\x3c\x77\xe5\x98\x38\x7e\xab\xbb\x0f\x75\x53\x1d\x9e\xae\xa7\x9f\xd0\x3d\xdc\x29\x6e\x8b\xc6\x39\xea\xaf\xbc\x80\x22\xa5\xa2\x56\x53\x7f\xef\x50\x63\xcc\x09\x63\xca\xa0\x0a\x90\xd2\x8a\x14\x65\x97\xcf\x34\xec\x6a\xe9\x7b\xe1\x6a\xf3\x9b\x5b\x2a\x33\x17\x72\xb4\x4a\x24\x36\x11\x2c\xe4\xa2\x29\x83\x97\x94\xb4\x18\x36\x36\x44\x8c\x0e\x20\x38\xcc\xba\xb0\x9c\xfb\x37\xe1\x3b\x88\x9b\x9b\xbf\xe1\xb0\xfe\xfc\x64\xcd\xa9\x0e\x87\xb8\xb9\xc5\x40\x29\x15\x48\x5b\x8e\xc6\x94\x58\xb4\xb1\x21\xb1\x52\x68\xb3\x65\x83\x92\x10\x00\x50\x71\x58\x58\xea\x7c\xe1\x5b\xaa\xf7\x61\x55\x49\xdf\x9f\x70\xec\x3f\x13\x71\x6f\x53\xb4\x67\x88\x2a\x8b\xa7\x18\x0a\xb2\x22\x0f\x48\x64\x4d\x0e\x86\x75\x64\x8e\x24\xd9\x84\x73\x5b\xdd\x9e\xfb\xf6\xd3\x46\x6e\xa7\x85\x76\x2b\x63\x5f\xf3\x62\xfc\x6f\x85\x1e\x5d\xf6\xc5\xaa\x22\xa0\xc0\xa1\xd7\x96\xc5\x71\x54\x8a\x00\xbd\x73\x3e\x11\x91\x62\x08\x00\xe1\x79\x4b\xf4\xbe\x40\x7c\xd7\xf6\xab\xea\xa6\xe2\xfe\xb6\x1b\xdb\x6a\x18\xd6\xd5\x28\xfd\xb6\x6e\xf0\x89\x23\xd9\xf6\xdd\xaa\x6d\x57\x1b\x19\xda\x5d\xcf\xb2\x57\x3a\x8c\x31\xd7\xe5\xa2\x01\x5b\x4c\x76\xa4\x1d\x25\x09\xd9\x16\xe5\x2d\x88\x4d\xb6\x84\xac\xb2\x55\x85\xc5\x96\x47\x2f\xed\xaf\xcf\xf1\x8e\x21\x17\x1b\x36\x32\x56\xd3\xbe\x28\x37\x4f\x94\x73\x33\x66\x8d\xcc\x55\x73\x68\x6d\x54\xa0\x49\x79\xe3\xb1\x04\x9f\x05\x5c\x2e\x46\x28\x0a\x24\xca\x00\xc1\x64\x26\x31\x0b\xb5\xee\xe0\x4e\x32\x9a\xa8\x9f\x58\x04\x5e\xcb\xe7\x80\x76\x92\x4d\x9d\x9b\x27\x6e\x36\x7a\x2d\x99\x3d\xd9\x69\x2e\xcd\x28\x7d\x83\x9b\x43\xbb\x27\x7d\xfd\x54\xff\xfd\x6a\x6a\x33\xa0\x27\x99\x6e\xe4\x66\x3f\xd9\x1b\x79\xa2\xc5\x7b\x2d\xc3\x63\xc0\x93\xcc\xf6\x75\xe6\xdb\x74\x3a\xa0\x2d\xb6\x19\x6e\x87\x6a\xd7\xd4\xa7\x4f\xd0\x70\x3b\xbb\x2f\x89\x31\x00\x6c\x23\x33\x68\xf4\x0a\x8a\xa6\xa9\x64\x80\x14\x4d\x36\x91\x44\xb1\x40\xc2\xa5\xd5\xc2\x9e\x6c\xb1\xcb\xb4\x4a\x56\x83\xf0\xae\x97\x8a\xea\x5c\xf7\xbb\xa7\x6e\x99\x98\xf1\x7a\xb0\x0f\x1c\xdd\xe1\x97\x4a\xf0\xa1\x60\xb1\xc5\xc6\x12\x40\xe5\xa2\xd1\x1a\xaf\x3d\xb9\x08\x4e\x7b\xd1\x18\x62\x58\x7a\xe2\xf3\x35\xe5\x69\x8e\x63\x8f\xcd\x50\xda\x7e\xfb\x46\xed\xee\xf9\x4e\xf3\xda\x35\x35\xb7\xf9\x90\x96\x37\xaa\xf6\x00\xf1\x79\x76\xcd\xdb\x9d\xb8\x07\x88\xdf\xb6\x9b\xf8\xde\x1d\x49\xae\xa4\xd9\x1f\x98\x56\x87\x7f\xc2\xae\x1e\x2a\xec\xea\x0a\x9b\xa6\x1d\xf1\xa4\x1b\x18\x0e\x23\x4c\x05\xf0\xdd\xa0\x73\x2b\x8d\xe6\x58\x40\xbc\x8b\x19\x43\xa6\x14\x83\x09\x8a\xc5\x81\x60\xf4\xd3\x82\xe3\x41\x39\x86\x47\xdb\xab\xaf\xcc\xbf\x41\x7d\x7e\x1e\xfa\x8e\xab\x61\xc4\x71\xf9\x2d\xc7\xaf\x9c\x82\x23\xe0\x13\xed\xfb\x8e\x17\x3b\x4e\xdf\x32\x3d\xcc\x9f\x6c\x64\x31\x46\x01\x42\x48\xd9\x25\x49\x10\x95\x77\x81\x13\x46\xad\x74\x82\x12\x5d\xd0\x36\xaa\xf2\xac\x93\x8d\xc3\x85\xb5\xea\xb1\x5b\x1f\x36\xb3\xfb\xf7\x15\x76\x5d\x3e\x6e\x85\x9f\xb0\xf8\x56\xe8\x51\xdf\x09\xe8\xac\x0d\xac\x8c\x77\x46\x88\x0a\x2a\xcd\x36\x82\x03\xca\x51\x7b\x53\x48\x95\xe0\xe1\x9b\xfd\xda\xe5\xc5\x7f\x2f\xff\xb8\xfc\x7f\x00\x00\x00\xff\xff\x0d\xef\xc7\x3f\x8d\x30\x00\x00")

func assetsDefault_manifestBytes() ([]byte, error) {
	return bindataRead(
		_assetsDefault_manifest,
		"assets/default_manifest",
	)
}

func assetsDefault_manifest() (*asset, error) {
	bytes, err := assetsDefault_manifestBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "assets/default_manifest", size: 12429, mode: os.FileMode(436), modTime: time.Unix(1510346406, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _schemaMashling_schema02Json = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xec\x58\x4d\x6f\xdb\x3c\x0c\xbe\xe7\x57\x08\x6e\x8f\x6d\xf5\x1e\xde\x53\x8e\xdb\x69\xa7\x0e\xd8\x6e\x43\x10\x28\x36\x6d\x2b\xb3\x25\x4f\x52\x1a\x04\x45\xfe\xfb\x60\xf9\x23\x56\x22\xc9\xce\xa2\x04\x29\xd0\x1e\x7a\x20\x29\x92\x0f\xf3\x90\x94\xfc\x3e\x43\x08\xa1\xe8\x51\xc6\x39\x94\x24\x9a\xa3\x28\x57\xaa\x9a\x63\xbc\x96\x9c\x3d\x37\xd2\x17\x2e\x32\x9c\x08\x92\xaa\xe7\xff\xfe\xc7\x8d\xec\x21\x7a\x6a\x4e\xaa\x5d\x05\xf5\x31\xbe\x5a\x43\xac\x3a\xa9\x80\x3f\x1b\x2a\x20\x89\xe6\xe8\x97\x96\x68\x69\x49\x64\x5e\x50\x96\x2d\xdb\x68\x4f\x07\x55\x46\x14\x6c\xc9\x2e\xd2\x92\x45\xeb\xa5\x12\xbc\x02\xa1\x28\xc8\x68\x8e\xde\xdd\x7e\x86\x4a\x23\x29\xa9\x04\x65\x59\xd4\x2b\xf7\x96\x88\xce\xc3\x06\xa2\x5e\x6b\x45\xd6\x6b\x19\x29\xe1\xe8\x84\x96\xbf\x81\x90\x94\x33\x9b\x2a\xe6\x2c\xa5\xd9\x46\x10\x45\x39\x93\x36\x0b\x25\x68\x96\x81\xb0\xea\xe0\x0d\x98\x5a\xe6\x84\x25\x85\xd7\xa2\xa0\xec\xb7\x8c\x0c\xed\xe2\x08\x99\xa3\xda\x26\x36\x9b\x06\xf9\x4a\xde\xfd\xed\x3d\x55\x09\xea\x34\xa1\xb2\x2a\xc8\x6e\x19\x3e\xdd\xce\x33\x2d\x49\x16\xda\x35\xc8\x58\xd0\x4a\x05\xaf\xc6\x11\xbb\x9c\xbe\xa9\x82\xd2\xad\xd6\x26\x8f\x02\xd2\x3a\xfc\x03\x4e\x20\xa5\x8c\x6a\x8f\xd8\x08\x70\x9a\x93\x23\x2f\x03\x0f\x11\xa2\xeb\xfc\x31\x38\x47\x74\x0f\x0f\xc7\x08\x70\x23\x38\x4d\x6f\x5e\x0b\x4b\xed\xfd\xea\x40\xfa\x11\x15\x1e\x45\xeb\x3a\x2c\x84\x99\xc7\x49\x44\x92\x44\xc7\x26\xc5\xf7\xe1\x48\x4c\x49\x21\x61\x66\xba\x68\x8f\x46\x83\x84\xcd\x55\x65\xb6\xc7\x4d\x76\x8d\xf6\x69\x91\x4b\x50\x8a\xb2\xec\xee\xb6\x40\x7b\xe6\x23\x4c\xd3\xbe\x84\xa3\x5e\xad\x3f\x68\x6f\xe5\x60\x98\xa7\x37\xc6\xb2\x45\x27\xac\x3e\x95\xfc\x1b\xcf\x07\x57\xa6\xae\x15\x3f\x69\xfc\x49\xe3\x0f\x4c\x63\x73\xc7\x87\x27\xb3\x97\x98\x9c\xc1\x6b\x6a\x3d\xec\xf8\x29\xbc\x01\x07\x56\x29\x08\x60\x31\xd8\x6b\xba\x98\xc2\x8b\x8b\x12\x38\x6c\xc0\xc9\x19\xdc\x59\x03\x5f\xad\xdd\x2a\x22\x88\xe7\xee\x73\x6f\xcd\x66\x41\x70\x60\x57\xe0\x8a\xf7\x9c\xb9\xb0\x38\x13\x39\x4a\x14\x71\x78\xd0\x7a\x9a\xf8\xb4\xf5\xed\xd4\x4e\x6d\x47\x52\x23\x14\x36\xd3\xf2\x59\x20\x4b\x21\x9c\xc6\x8e\x2b\x31\x6a\x01\x4e\x8e\xe3\x63\xcd\x58\x9c\xe6\x22\x7f\x5e\x20\xb7\x3b\xd4\x72\x85\x6c\x0a\xd5\x7d\xa1\x92\x73\x8c\x33\xaa\xf2\xcd\xea\x25\xe6\x25\xfe\xf9\xed\xcb\xd7\xd7\x1f\x3c\x55\x5b\x22\x00\xa7\x05\xcf\xf8\x73\xcc\x99\x12\x74\x85\x57\x05\x5f\xe1\x92\x48\x05\x02\x93\xb8\x66\x5b\x6d\xb0\x1d\x3c\x32\xda\x6f\x5a\x2f\x6b\xe9\x9a\x5e\xc8\xda\x2a\x9e\x32\x4c\xdb\x4a\x76\xd7\x81\x16\x9c\x7e\xf8\x05\xdd\x6e\xbe\x0f\x51\x09\x95\x15\x51\x71\x0e\x17\x5e\xcc\xc6\x5f\x92\xe6\xdb\xce\x51\xfe\x09\xcf\xcd\x70\xe3\x71\x80\xfd\x66\x59\x7b\xe7\x21\x9a\x3c\x13\xb5\xa5\xf7\x73\x07\x72\x4f\x38\x74\xc6\x94\xd3\xb6\x74\x7c\x2c\xa0\x73\x66\x10\xf2\xcf\x21\x34\x04\x17\x3e\xf0\xb9\x93\xe2\x2a\x6d\x3f\x6b\xfe\xef\x67\x7f\x03\x00\x00\xff\xff\x39\x9c\x5e\x55\xca\x17\x00\x00")

func schemaMashling_schema02JsonBytes() ([]byte, error) {
	return bindataRead(
		_schemaMashling_schema02Json,
		"schema/mashling_schema-0.2.json",
	)
}

func schemaMashling_schema02Json() (*asset, error) {
	bytes, err := schemaMashling_schema02JsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "schema/mashling_schema-0.2.json", size: 6090, mode: os.FileMode(436), modTime: time.Unix(1509385901, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"assets/banner.txt": assetsBannerTxt,
	"assets/default_manifest": assetsDefault_manifest,
	"schema/mashling_schema-0.2.json": schemaMashling_schema02Json,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}
var _bintree = &bintree{nil, map[string]*bintree{
	"assets": &bintree{nil, map[string]*bintree{
		"banner.txt": &bintree{assetsBannerTxt, map[string]*bintree{}},
		"default_manifest": &bintree{assetsDefault_manifest, map[string]*bintree{}},
	}},
	"schema": &bintree{nil, map[string]*bintree{
		"mashling_schema-0.2.json": &bintree{schemaMashling_schema02Json, map[string]*bintree{}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}

