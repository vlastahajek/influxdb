package upgrade

// Configuration file upgrade implementation.
// The strategy is to transform only those entries for which rule exists.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"go.uber.org/zap"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// configMapRules is a map of transformation rules
var configMapRules = map[string]string{
	"reporting-disabled": "reporting-disabled",
	"data.dir": "engine-path",
	"data.wal-fsync-delay": "storage-wal-fsync-delay",
	"data.validate-keys": "storage-validate-keys",
	"data.cache-max-memory-size": "storage-cache-max-memory-size",
	"data.cache-snapshot-memory-size": "storage-cache-snapshot-memory-size",
	"data.cache-snapshot-write-cold-duration": "storage-cache-snapshot-write-cold-duration",
	"data.compact-full-write-cold-duration": "storage-compact-full-write-cold-duration",
	"data.compact-throughput-burst": "storage-compact-throughput-burst",
	"data.max-concurrent-compactions": "storage-max-concurrent-compactions",
	"data.max-index-log-file-size": "storage-max-index-log-file-size",
	"data.series-id-set-cache-size": "storage-series-id-set-cache-size",
	"data.series-file-max-concurrent-snapshot-compactions": "storage-series-file-max-concurrent-snapshot-compactions",
	"data.tsm-use-madv-willneed": "storage-tsm-use-madv-willneed",
	"retention.check-interval": "storage-retention-check-interval",
	"shard-precreation.check-interval": "storage-shard-precreator-check-interval",
	"shard-precreation.advance-period": "storage-shard-precreator-advance-period",
	"coordinator.max-concurrent-queries": "query-concurrency",
	"coordinator.max-select-point": "influxql-max-select-point",
	"coordinator.max-select-series": "influxql-max-select-series",
	"coordinator.max-select-buckets": "influxql-max-select-buckets",
	"logging.level": "log-level",
	"http.bind-address": "http-bind-address",
	"http.https-certificate": "tls-cert",
	"http.https-private-key": "tls-key",
}

// upgradeConfig upgrades existing 1.x (ie. typically influxdb.conf) configuration file to 2.x influxdb.toml file.
func upgradeConfig(configFile string, targetOptions optionsV2, log *zap.Logger) (*configV1, error) {
	// create and initialize helper
	cu := &configUpgrader{
		rules: configMapRules,
		log: log,
	}

	// load 1.x config content into byte array
	bs, err := cu.load(configFile)
	if err != nil {
		return nil, err
	}

	// parse it into simplified v1 config used as return value
	var configV1 configV1
	_, err = toml.Decode(string(bs), &configV1)
	if err != nil {
		return nil, err
	}

	// parse into a generic config map
	var cAny map[string]interface{}
	_, err = toml.Decode(string(bs), &cAny)
	if err != nil {
		return nil, err
	}

	// transform the config according to rules
	cTransformed := cu.transform(cAny)
	if err != nil {
		return nil, err
	}

	// update new config with upgrade command options
	cu.updateV2Config(cTransformed, targetOptions)

	// backup existing 2.x config if already exists (it should not)
	configFileV2 := strings.TrimSuffix(configFile, filepath.Ext(configFile)) + ".toml"
	err = cu.backupIfExists(configFileV2)
	if err != nil {
		return nil, err
	}

	// save new config
	err = cu.save(cTransformed, configFileV2)
	if err != nil {
		return nil, err
	}

	log.Info("Config file upgraded.",
		zap.String("1.x config", configFile),
		zap.String("2.x config", configFileV2))

	return &configV1, nil
}

// configUpgrader is a helper used by `upgrade-config` command.
type configUpgrader struct {
	rules map[string]string
	log   *zap.Logger
}

func (cu *configUpgrader) backupIfExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	source, err := os.Open(path)
	if err != nil {
		return err
	}
	defer source.Close()

	backupFile := path + "~"
	if _, err := os.Stat(backupFile); !os.IsNotExist(err) {
		errMsg := fmt.Sprintf("upgrade: config file backup %s already exist", backupFile)
		return errors.New(errMsg)
	}

	destination, err := os.Create(backupFile)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)

	return err
}

func (cu *configUpgrader) updateV2Config(config map[string]interface{}, targetOptions optionsV2) {
	if targetOptions.enginePath != "" {
		config["engine-path"] = targetOptions.enginePath
	}
	if targetOptions.boltPath != "" {
		config["bolt-path"] = targetOptions.boltPath
	}
}

func (cu *configUpgrader) load(path string) ([]byte, error) {
	bs, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// From master-1.x/cmd/influxd/run/config.go:
	// Handle any potential Byte-Order-Marks that may be in the config file.
	// This is for Windows compatibility only.
	// See https://github.com/influxdata/telegraf/issues/1378 and
	// https://github.com/influxdata/influxdb/issues/8965.
	bom := unicode.BOMOverride(transform.Nop)
	bs, _, err = transform.Bytes(bom, bs)

	return bs, err
}

func (cu *configUpgrader) save(config map[string]interface{}, path string) error {
	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(&config); err != nil {
		return err
	}

	return ioutil.WriteFile(path, buf.Bytes(), 0666)
}

// Credits: @rogpeppe (Roger Peppe)

func (cu *configUpgrader) transform(x map[string]interface{}) map[string]interface{} {
	res := make(map[string]interface{})
	for old, new := range cu.rules {
		val, ok := cu.lookup(x, old)
		if ok {
			res[new] = val
		}
	}

	return res
}

func (cu *configUpgrader) lookup(x map[string]interface{}, path string) (interface{}, bool) {
	for {
		elem := path
		rest := ""
		if i := strings.Index(path, "."); i != -1 {
			elem, rest = path[0:i], path[i+1:]
		}
		val, ok := x[elem]
		if rest == "" {
			return val, ok
		}
		child, ok := val.(map[string]interface{})
		if !ok {
			return nil, false
		}
		path, x = rest, child
	}
}
