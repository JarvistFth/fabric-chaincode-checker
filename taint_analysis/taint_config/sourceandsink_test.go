package taint_config

import "testing"

func TestNewCfgFromFile(t *testing.T) {
	cfg,err := NewSinkAndSourceCfgFromFile("../../config/sourceandsink.json")

	if err != nil{
		t.Error(err.Error())
		return
	}

	log.Info(cfg.String())
}
