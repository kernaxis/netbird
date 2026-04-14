//go:build linux && !android

package server

import (
	"fmt"
	"image"

	"github.com/jezek/xgb/shm"
	"github.com/jezek/xgb/xproto"
	"golang.org/x/sys/unix"
)

func (c *X11Capturer) initSHM() error {
	if err := shm.Init(c.conn); err != nil {
		return fmt.Errorf("init SHM extension: %w", err)
	}

	size := c.w * c.h * 4
	id, err := unix.SysvShmGet(unix.IPC_PRIVATE, size, unix.IPC_CREAT|0600)
	if err != nil {
		return fmt.Errorf("shmget: %w", err)
	}

	addr, err := unix.SysvShmAttach(id, 0, 0)
	if err != nil {
		unix.SysvShmCtl(id, unix.IPC_RMID, nil)
		return fmt.Errorf("shmat: %w", err)
	}

	unix.SysvShmCtl(id, unix.IPC_RMID, nil)

	seg, err := shm.NewSegId(c.conn)
	if err != nil {
		unix.SysvShmDetach(addr)
		return fmt.Errorf("new SHM seg: %w", err)
	}

	if err := shm.AttachChecked(c.conn, seg, uint32(id), false).Check(); err != nil {
		unix.SysvShmDetach(addr)
		return fmt.Errorf("SHM attach to X: %w", err)
	}

	c.shmID = id
	c.shmAddr = addr
	c.shmSeg = uint32(seg)
	c.useSHM = true
	return nil
}

func (c *X11Capturer) captureSHM() (*image.RGBA, error) {
	cookie := shm.GetImage(c.conn, xproto.Drawable(c.screen.Root),
		0, 0, uint16(c.w), uint16(c.h), 0xFFFFFFFF,
		xproto.ImageFormatZPixmap, shm.Seg(c.shmSeg), 0)

	_, err := cookie.Reply()
	if err != nil {
		return nil, fmt.Errorf("SHM GetImage: %w", err)
	}

	img := image.NewRGBA(image.Rect(0, 0, c.w, c.h))
	n := c.w * c.h * 4

	for i := 0; i < n; i += 4 {
		img.Pix[i+0] = c.shmAddr[i+2] // R
		img.Pix[i+1] = c.shmAddr[i+1] // G
		img.Pix[i+2] = c.shmAddr[i+0] // B
		img.Pix[i+3] = 0xff
	}
	return img, nil
}

func (c *X11Capturer) closeSHM() {
	if c.useSHM {
		shm.Detach(c.conn, shm.Seg(c.shmSeg))
		unix.SysvShmDetach(c.shmAddr)
	}
}
