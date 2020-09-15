package upgrade

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/influxdata/influxdb/v2"
	"github.com/influxdata/influxdb/v2/v1/services/meta"
	"github.com/influxdata/influxql"
	"github.com/spf13/cobra"
)

// TODO for testing purposes
var generateSecurityScriptCommand = &cobra.Command{
	Use:   "generate-security-script",
	Short: "Generate security script",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		v1, err := newInfluxDBv1(&options.source)
		if err != nil {
			return err
		}
		v2, err := newInfluxDBv2(ctx, &options.target)
		if err != nil {
			return err
		}
		return generateSecurityScript(ctx, v1, v2)
	},
}

func init() {
	flags := generateSecurityScriptCommand.Flags()

	v1dir, err := influxDirV1()
	if err != nil {
		panic("error fetching default InfluxDB 1.x dir: " + err.Error())
	}

	flags.StringVar(&options.source.metaDir, "v1-meta-dir", filepath.Join(v1dir, "meta"), "Path to 1.x meta.db directory")
	flags.StringVar(&options.target.orgName, "v2-org", "", "Organization name")
	flags.StringVar(&options.securityScriptPath, "security-script-path", "stdout", "Security script path")
}

// Generates security upgrade script.
func generateSecurityScript(ctx context.Context, v1 *influxDBv1, v2 *influxDBv2) error {
	// create helper
	helper := &securityScriptHelper{}
	if err := helper.init(); err != nil {
		return err
	}

	// try to guess target org name if necessary
	var targetOrg = options.target.orgName
	if targetOrg == "" {
		orgs, _, err := v2.ts.FindOrganizations(ctx, influxdb.OrganizationFilter{})
		if err != nil {
			return err
		}
		targetOrg, err = helper.guessTargetOrg(orgs)
		if err != nil {
			return err
		}
	}

	// first check if all target buckets exists in 2.x
	buckets, _, err := v2.ts.FindBuckets(ctx, influxdb.BucketFilter{
		Org: &targetOrg,
	})
	if err != nil {
		return err
	}
	databases := make(map[string]string)
	v1meta := v1.meta
	proceed := helper.checkDbMapping(v1meta, databases, buckets)
	if !proceed {
		return errors.New("there were errors/warnings, please fix them and run the command again")
	}

	// create output
	var output *os.File
	if options.securityScriptPath == "" {
		output = os.Stdout
	} else {
		output, err = os.OpenFile(options.securityScriptPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
		if err != nil {
			return errors.New(fmt.Sprintf("upgrade: cannot create security script: %v", err))
		}
	}

	// script printing helper funcs
	scriptf := func(format string, args ...interface{}) {
		fmt.Fprintf(output, format, args...)
	}
	scriptln := func(text string) {
		fmt.Fprintln(output, text)
	}
	script := func() {
		fmt.Fprintln(output, "")
	}

	// generate the script
	var br, todo, fi string
	if helper.isWin() {
		br = "^"
		todo = "REM"
		fi = ")"
		scriptln("@ECHO OFF")
		script()
	} else {
		br = "\\"
		todo = "#"
		fi = "fi"
		scriptln("#!/bin/sh")
		script()
	}
	for _, row := range helper.sortUserInfo(v1meta.Users()) {
		username := row.Name
		varname := helper.shUserVar(username)
		if row.Admin {
			scriptf("%s=no %s %s is 1.x admin, will not be upgraded automatically\n",
				varname, todo, username)
		} else {
			scriptf("%s=yes %s %s\n", varname, todo, username)
		}
	}
	script()
	scriptln(todo)
	scriptf("%s INDIVIDUAL USER UPGRADES\n", todo)
	scriptln(todo)
	script()
	for _, row := range helper.sortUserInfo(v1meta.Users()) {
		username := row.Name
		if helper.isWin() {
			scriptf("IF /I \"%%%s\" == \"yes\" (\n", helper.shUserVar(username))
		} else {
			scriptf("if [ \"$%s\" = \"yes\" ]; then\n", helper.shUserVar(username))
		}
		if row.Admin {
			scriptf("  echo \"User %s is 1.x admin and should be added & invited manually to 2.x if needed\"\n", username)
			scriptf("  %s add & invite user %s in the UI\n", todo, username)
			scriptln(fi)
			script()
			continue
		}
		password := helper.generatePassword(8) // influx user create requires password
		scriptf("  echo \"Creating user %s with password %s in %s organization...\" && %s\n", username, password, targetOrg, br)
		influxCreateUser := fmt.Sprintf("influx user create --name=%s --password=%s --org=%s", username, password, targetOrg)
		scriptf("  %s && %s\n", influxCreateUser, br)
		readAccess := make([]string, 0)
		writeAccess := make([]string, 0)
		for database, permission := range row.Privileges {
			id := databases[database]
			switch permission {
			case influxql.ReadPrivilege:
				readAccess = append(readAccess, id)
			case influxql.WritePrivilege:
				writeAccess = append(writeAccess, id)
			case influxql.AllPrivileges:
				readAccess = append(readAccess, id)
				writeAccess = append(writeAccess, id)
			}
		}
		var readBucketArg, writeBucketArg string
		if len(readAccess) > 0 {
			readBucketArg = fmt.Sprintf("--read-bucket=%s", strings.Join(readAccess, ","))
		}
		if len(writeAccess) > 0 {
			writeBucketArg = fmt.Sprintf("--write-bucket=%s", strings.Join(writeAccess, ","))
		}
		scriptf("  echo \"Creating authorization token...\" && %s\n", br)
		influxCreateAuth := fmt.Sprintf("influx auth create --user=%s --org=%s %s %s",
			row.Name, targetOrg, readBucketArg, writeBucketArg)
		scriptf("  %s\n", influxCreateAuth)
		scriptln(fi)
		script()
		// sample output per user:
		// ID			Name
		// 064b437f88377000	xyz1
		// ID			Token												User Name	User ID			Permissions
		// 064b485f4fe3a000	aysw_eMIF46WxKx8o0oz9bNmMVGL09AAg1Scoo1ynFJSW4uC2P3O8HyVy8NTISbNltNDFr7jAyQui3KS-ahpsQ==	xyz		064b435351b77000	[read:orgs/b20841b0f84c3b7e/buckets/8213da1997b3d89e write:orgs/b20841b0f84c3b7e/buckets/8213da1997b3d89e]
	}

	// when output goes to file, print info on stderr
	if options.securityScriptPath != "" {
		fmt.Fprintf(os.Stderr, "upgrade: security upgrade script saved to %s\n", options.securityScriptPath)
	}

	return nil
}

// private type used by `generate-security-script` command
type securityScriptHelper struct {
	shReg *regexp.Regexp
}

func (h *securityScriptHelper) init() error {
	reg, err := regexp.Compile("[^a-zA-Z0-9]+")
	if err != nil {
		return errors.New(fmt.Sprintf("upgrade: error preparing security script: %v", err))
	}
	h.shReg = reg
	return nil
}

func (h *securityScriptHelper) guessTargetOrg(orgs []*influxdb.Organization) (name string, err error) {
	switch len(orgs) {
	case 0:
		err = errors.New("upgrade: no organization exists in InfluxDB 2.x yet, create one")
	case 1:
		name = orgs[0].Name
	default:
		var n []string
		for _, org := range orgs {
			n = append(n, org.Name)
		}
		err = errors.New(fmt.Sprintf("upgrade: multiple organizations exists in InfluxDB 2.x [%s], select one", strings.Join(n, ",")))
	}
	return
}

func (h *securityScriptHelper) checkDbMapping(meta *meta.Client, databases map[string]string, buckets []*influxdb.Bucket) bool {
	ok := true
	for _, row := range meta.Users() {
		for database, _ := range row.Privileges {
			if _, ok := databases[database]; ok {
				continue
			}
			id := h.getBucketID(buckets, database)
			if id == "" {
				fmt.Fprintf(os.Stderr, "warning: bucket %s does not exist\n", database)
				ok = false
			}
			databases[database] = id
		}
	}

	return ok
}

func (h *securityScriptHelper) getBucketID(buckets []*influxdb.Bucket, name string) string {
	for _, bucket := range buckets {
		if bucket.Name == name {
			return bucket.ID.String()
		}
	}
	return ""
}

func (h *securityScriptHelper) shUserVar(name string) string {
	return "UPGRADE_USER_" + h.shReg.ReplaceAllString(name, "_")
}

func (h *securityScriptHelper) sortUserInfo(info []meta.UserInfo) []meta.UserInfo {
	sort.Slice(info, func(i, j int) bool {
		return info[i].Name < info[j].Name
	})
	return info
}

func (h *securityScriptHelper) generatePassword(length int) string {
	lowerCharSet := "abcdefghijklmnopqrstuvwxyz"
	upperCharSet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	specialCharSet := "" //".!@#$%"
	numberSet := "0123456789"
	allCharSet := lowerCharSet + upperCharSet + specialCharSet + numberSet
	rand.Seed(time.Now().UnixNano())
	chars := []rune(allCharSet)
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	return b.String()
}

func (h *securityScriptHelper) isWin() bool {
	return runtime.GOOS == "windows"
}
