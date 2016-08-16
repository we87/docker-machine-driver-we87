package main

import (
	"github.com/docker/machine/libmachine/drivers/plugin"
	"github.com/we87/docker-machine-driver-we87/we87"
)

func main() {
	plugin.RegisterDriver(we87.NewDriver("", ""))
}
