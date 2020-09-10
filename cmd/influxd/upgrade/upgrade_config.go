package upgrade

// This file contains code for backup and v1 config file in-place upgrade.
// It supports basic restructuring (caveat: changing structure inside existing
// array or to new array may not work, but it is not required).
// Transformation rules are in `upgrade_config.properties` file:
// - when target path is empty, entry is removed
// - when target path is different from source, entry is moved
// Otherwise, source entry is copied to the same place in the target config.

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	//itoml "github.com/influxdata/influxdb/v2/toml"
	"github.com/spf13/cobra"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

var upgradeConfigCommand = &cobra.Command{
	Use:   "upgrade-config",
	Short: "Upgrade InfluxDB 1.x config to 2.x",
	RunE: func(cmd *cobra.Command, args []string) error {
		return upgradeConfig(options.configFile)
	},
}

func init() {
	flags := upgradeConfigCommand.Flags()
	flags.StringVar(&options.configFile, "config-file", "/etc/influxdb/influxdb.conf", "Path to config file")
}

// Backups existing config file and updates it with upgraded config.
func upgradeConfig(configFile string) error {
	configUpgradeProperties, err := AssetString("upgrade_config.properties")
	if err != nil {
		return err
	}
	cu := newConfigUpgrader(configUpgradeProperties)
	err = cu.backup(configFile)
	if err != nil {
		return err
	}
	c, err := cu.transform(configFile)
	if err != nil {
		return err
	}
	err = cu.save(c, configFile)
	if err != nil {
		return err
	}

	return nil
}

type properties map[string]string   // private type used by `upgrade-config` command
type table = map[string]interface{} // private type used by `upgrade-config` command
type config = table                 // private type used by `upgrade-config` command

// private type used by `upgrade-config` command
type configUpgrader struct {
	rules  properties
	config config
}

// private function used by `upgrade-config` command
func newConfigUpgrader(rules string) *configUpgrader {
	cm := &configUpgrader{}
	cm.init(rules)
	return cm
}

func (cu *configUpgrader) backup(path string) error {
	sourceFileStat, err := os.Stat(path)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return errors.New("upgrade: '" + path + "' is not a regular file")
	}

	source, err := os.Open(path)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(path + "~")
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)

	return err
}

func (cu *configUpgrader) save(c config, path string) error {
	buf := new(bytes.Buffer)
	if err := toml.NewEncoder(buf).Encode(&c); err != nil {
		return err
	}

	return ioutil.WriteFile(path, buf.Bytes(), 0666)
}

func (cu *configUpgrader) transform(path string) (config, error) {
	c, err := cu.parse(path)
	if err != nil {
		return nil, err
	}
	//err = itoml.ApplyEnvOverrides(os.Getenv, "INFLUXDB", c)
	//if err != nil {
	//	return nil, err
	//}
	cu.config = make(config)
	cu.process(c, nil, -1)
	return cu.config, nil
}

func (cu *configUpgrader) parse(path string) (config, error) {
	bs, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Handle any potential Byte-Order-Marks that may be in the config file.
	// This is for Windows compatibility only.
	// See https://github.com/influxdata/telegraf/issues/1378 and
	// https://github.com/influxdata/influxdb/issues/8965.
	bom := unicode.BOMOverride(transform.Nop)
	bs, _, err = transform.Bytes(bom, bs)
	if err != nil {
		return nil, err
	}

	var c config
	_, err = toml.Decode(string(bs), &c)
	return c, err
}

func (cu *configUpgrader) init(rules string) {
	cu.rules = make(properties)
	scanner := bufio.NewScanner(strings.NewReader(rules))
	for scanner.Scan() {
		line := scanner.Text()
		rule := strings.SplitN(line, "=", 2)
		if len(rule) == 2 {
			sourceKey := strings.Trim(rule[0], " ")
			targetKey := strings.Trim(rule[1], " ")
			cu.rules[sourceKey] = targetKey
		}
	}
}

func (cu *configUpgrader) convert(path []string) ([]string, bool) {
	fqn := strings.Join(path, ".")
	target, ok := cu.rules[fqn]
	if ok {
		if target == "" {
			return nil, true
		}
		return strings.Split(target, "."), true
	}
	return path, false
}

// flat copy ie. without values for maps and arrays
func (cu *configUpgrader) add(v interface{}, source []string, target []string, index int) {
	var c table
	c = cu.config
	for len(target) > 1 {
		n := target[0]
		u, ok := c[n]
		if !ok {
			u = make(table)
			c[n] = u
		}
		if uc, ok := u.(table); ok {
			c = uc
		}
		if uc, ok := u.([]table); ok {
			if uc[index] == nil {
				uc[index] = make(table)
			}
			c = uc[index]
		}
		target = target[1:]
	}
	n := target[0]
	switch vv := v.(type) {
	case table:
		c[n] = make(table)
	case []table:
		c[n] = make([]table, len(vv))
	default:
		c[n] = v
	}
}

func (cu *configUpgrader) process(c interface{}, path []string, index int) []string {
	switch v := c.(type) {
	case table:
		for key, value := range v {
			path = append(path, key)
			target, changed := cu.convert(path)
			if target == nil { // entry is removed
				delete(v, key)
				path = cu.pop(path)
				continue
			}
			if changed { // entry is moved
				cu.add(value, path, target, index)
			} else { // entry remains as is
				cu.add(value, path, path, index)
			}
			path = cu.process(value, path, -1)
		}
		if index == -1 {
			path = cu.pop(path)
		}
	case []table:
		for i, value := range v {
			path = cu.process(value, path, i)
		}
		path = cu.pop(path)
	default:
		path = cu.pop(path)
	}

	return path
}

func (cu *configUpgrader) pop(path []string) []string {
	if len(path) > 0 {
		path = path[:len(path)-1]
	}

	return path
}
