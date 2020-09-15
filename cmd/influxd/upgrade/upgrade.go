//go:generate env GO111MODULE=on go run github.com/kevinburke/go-bindata/go-bindata -o upgrade_gen.go -ignore go -pkg upgrade .

package upgrade

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/influxdata/influxdb/v2"
	"github.com/influxdata/influxdb/v2/bolt"
	"github.com/influxdata/influxdb/v2/dbrp"
	"github.com/influxdata/influxdb/v2/internal/fs"
	"github.com/influxdata/influxdb/v2/kit/metric"
	"github.com/influxdata/influxdb/v2/kit/prom"
	"github.com/influxdata/influxdb/v2/kv"
	"github.com/influxdata/influxdb/v2/kv/migration"
	"github.com/influxdata/influxdb/v2/kv/migration/all"
	fs2 "github.com/influxdata/influxdb/v2/pkg/fs"
	"github.com/influxdata/influxdb/v2/storage"
	options2 "github.com/influxdata/influxdb/v2/task/options"
	"github.com/influxdata/influxdb/v2/tenant"
	"github.com/influxdata/influxdb/v2/v1/services/meta"
	"github.com/influxdata/influxdb/v2/v1/services/meta/filestore"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var Command = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrade a 1.x version of InfluxDB",
	RunE:  runUpgradeE,
}

type optionsV1 struct {
	metaDir string
}

type optionsV2 struct {
	boltPath  string
	userName  string
	password  string
	orgName   string
	bucket    string
	token     string
	retention string
}

var options = struct {
	// flags for source InfluxDB
	source optionsV1

	// flags for target InfluxDB
	target optionsV2

	// common flags
	configFile string

}{}

func init() {
	flags := Command.Flags()
	// source flags
	v1dir, err := influxDirV1()
	if err != nil {
		panic("error fetching default InfluxDB 1.x dir: " + err.Error())
	}

	flags.StringVar(&options.source.metaDir, "v1-meta-dir", filepath.Join(v1dir, "meta"), "Path to 1.x meta.db directory")

	// target flags
	v2dir, err := fs.InfluxDir()
	if err != nil {
		panic("error fetching default InfluxDB 2.0 dir: " + err.Error())
	}

	flags.StringVar(&options.target.boltPath, "v2-bolt-path", filepath.Join(v2dir, "influxd.bolt"), "Path to 2.0 metadata")
	flags.StringVarP(&options.target.userName, "username", "u", "", "primary username")
	flags.StringVarP(&options.target.password, "password", "p", "", "password for username")
	flags.StringVarP(&options.target.orgName, "org", "o", "", "primary organization name")
	flags.StringVarP(&options.target.bucket, "bucket", "b", "", "primary bucket name")
	flags.StringVarP(&options.target.retention, "retention", "r", "", "Duration bucket will retain data. 0 is infinite. Default is 0.")
	flags.StringVarP(&options.target.token, "token", "t", "", "token for username, else auto-generated")

	// common flags
	flags.StringVar(&options.configFile, "config-file", "/etc/influxdb/influxdb.conf", "Path to config file")

	// add sub commands
	Command.AddCommand(v1DumpMetaCommand)
	Command.AddCommand(v2DumpMetaCommand)
	Command.AddCommand(upgradeConfigCommand) // TODO for testing purposes
}

type influxDBv1 struct {
	meta *meta.Client
}

type influxDBv2 struct {
	log         *zap.Logger
	boltClient  *bolt.Client
	store       *bolt.KVStore
	kvStore     kv.SchemaStore
	tenantStore *tenant.Store
	ts          *tenant.Service
	dbrpSvc     influxdb.DBRPMappingServiceV2
	bucketSvc   influxdb.BucketService
	onboardSvc  influxdb.OnboardingService
	kvService   *kv.Service
	meta        *meta.Client
	enginePath  string
}

func runUpgradeE(*cobra.Command, []string) error {
	ctx := context.Background()

	if options.target.userName == "" ||
		options.target.password == "" ||
		options.target.orgName == "" ||
		options.target.bucket == "" {
		return errors.New("missing mandatory param")
	}

	v1, err := newInfluxDBv1(&options.source)
	if err != nil {
		return err
	}
	_ = v1

	v2, err := newInfluxDBv2(ctx, &options.target)
	if err != nil {
		return err
	}

	log := v2.log.With(zap.String("service", "upgrade"))
	err = upgradeDatabases(ctx, v1, v2, log)
	if err != nil {
		return err
	}

	// TODO call upgradeConfig()

	log.Info("Upgrade successfully completed. Start service now")

	return nil
}

func upgradeDatabases(ctx context.Context, v1 *influxDBv1, v2 *influxDBv2, log *zap.Logger) (err error) {

	// 1. Onboard the initial admin user
	// if onboarding has been already completed do not run now
	canOnboard, err := v2.onboardSvc.IsOnboarding(ctx)
	if err != nil {
		return err
	}
	orgID := influxdb.ID(0)
	if canOnboard {
		req := &influxdb.OnboardingRequest{
			User:     options.target.userName,
			Password: options.target.password,
			Org:      options.target.orgName,
			Bucket:   options.target.bucket,
			Token:    options.target.token,
		}
		dur, err := rawDurationToTimeDuration(options.target.retention)
		if dur > 0 {
			req.RetentionPeriod = uint(dur / time.Hour)
		}
		log.Debug("onboarding")
		res, err := v2.onboardSvc.OnboardInitialUser(ctx, req)
		if err != nil {
			return fmt.Errorf("onboarding error: %w", err)
		}
		orgID = res.Org.ID
	} else {
		return errors.New("InfluxDB has been already set up")
	}
	// 2. read each database / retention policy from v1.meta and create bucket db-name/rp-name
	//newBucket := v2.ts.CreateBucket(ctx, Bucket{})
	//
	// 3. create database in v2.meta
	// v2.meta.CreateDatabase(newBucket.ID.String())
	// copy shard info from v1.meta

	if len(v1.meta.Databases()) > 0 {
		// Check space
		log.Info("Checking space")
		v1dir := filepath.Clean(filepath.Join(options.source.metaDir, ".."))
		sourceDataPath := filepath.Join(v1dir, "data")
		size, err := fs2.DirSize(sourceDataPath)
		if err != nil {
			return fmt.Errorf("error opening getting size of %s: %w", sourceDataPath, err)
		}
		v2dir := filepath.Dir(options.target.boltPath)
		diskInfo, err := fs2.DiskUsage(v2dir)
		if err != nil {
			return fmt.Errorf("error getting info of disk %s: %w", v2dir, err)
		}
		log.Debug("disk space info",
			zap.String("Free space", fs2.HumanSize(diskInfo.Free)),
			zap.String("Needed space", fs2.HumanSize(size)))
		if size > diskInfo.Free {
			return fmt.Errorf("not enough space on target disk of %s: need %d, available %d ", v2dir, size, diskInfo.Free)
		}
		log.Info("Creating databases")
		database2bucketID := make(map[string]string)
		for _, db := range v1.meta.Databases() {
			if db.Name[0] == '_' {
				log.Info("skipping internal ",
					zap.String("database", db.Name))
				continue
			}
			log.Info("upgrading database ",
				zap.String("database", db.Name))

			for _, rp := range db.RetentionPolicies {
				bucket := &influxdb.Bucket{
					OrgID:               orgID,
					Type:                influxdb.BucketTypeUser,
					Name:                db.Name + "-" + rp.Name,
					Description:         fmt.Sprintf("Upgraded from v1 database %s with retention policy %s", db.Name, rp.Name),
					RetentionPolicyName: rp.Name,
					RetentionPeriod:     rp.Duration,
				}
				log.Debug("Creating bucket ",
					zap.String("Bucket", bucket.Name))

				err := v2.bucketSvc.CreateBucket(ctx, bucket)
				if err != nil {
					return fmt.Errorf("error creating bucket %s: %w", bucket.Name, err)

				}

				database2bucketID[db.Name] = bucket.ID.String()

				log.Debug("Creating database with retention policy",
					zap.String("database", bucket.ID.String()))

				dbv2, err := v2.meta.CreateDatabaseWithRetentionPolicy(bucket.ID.String(), rp.ToSpec())
				if err != nil {
					return fmt.Errorf("error creating database %s: %w", bucket.ID.String(), err)
				}

				mapping := &influxdb.DBRPMappingV2{
					Database:        db.Name,
					RetentionPolicy: rp.Name,
					Default:         true,
					OrganizationID:  orgID,
					BucketID:        bucket.ID,
				}

				log.Debug("Creating mapping",
					zap.String("database", mapping.Database),
					zap.String("retention policy", mapping.RetentionPolicy),
					zap.String("orgID", mapping.OrganizationID.String()),
					zap.String("bucketID", mapping.BucketID.String()))

				err = v2.dbrpSvc.Create(ctx, mapping)
				if err != nil {
					return fmt.Errorf("error creating mapping  %s/%s -> Org %s, bucket %s: %w", mapping.Database, mapping.RetentionPolicy, mapping.OrganizationID.String(), mapping.BucketID.String(), err)
				}
				for _, sg := range rp.ShardGroups {
					log.Debug("Creating shard group",
						zap.String("database", dbv2.Name),
						zap.String("retention policy", dbv2.DefaultRetentionPolicy),
						zap.Time("time", sg.StartTime))
					_, err := v2.meta.CreateShardGroupWithShards(dbv2.Name, dbv2.DefaultRetentionPolicy, sg.StartTime, sg.Shards...)
					if err != nil {
						return fmt.Errorf("error creating database %s: %w", bucket.ID.String(), err)
					}
				}
			}
		}
		log.Info("Copying data")
		targetPath := filepath.Join(v2dir, "engine", "data")
		err = fs2.CopyDir(sourceDataPath,
			targetPath,
			func(name string) string {
				if newName, ok := database2bucketID[name]; ok {
					return newName
				}
				return name
			},
			func(path string) bool {
				base := filepath.Base(path)
				if base == "_series" ||
					(len(base) > 0 && base[0] == '_') || //skip internal databases
					base == "index" {
					return true
				}
				return false
			},
			nil)
		if err != nil {
			return fmt.Errorf("error copying v1 data from %s to %s: %w", sourceDataPath, targetPath, err)
		}
	} else {
		log.Info("No database found")
	}
	return nil
}

func newInfluxDBv1(opts *optionsV1) (svc *influxDBv1, err error) {
	svc = &influxDBv1{}
	svc.meta, err = openV1Meta(opts.metaDir)
	if err != nil {
		return nil, fmt.Errorf("error opening 1.x meta.db: %w", err)
	}

	return svc, nil
}

func newInfluxDBv2(ctx context.Context, opts *optionsV2) (svc *influxDBv2, err error) {
	log, _ := zap.NewDevelopment()
	reg := prom.NewRegistry(log.With(zap.String("service", "prom_registry")))

	svc = &influxDBv2{}
	svc.log = log

	// *********************
	// V2 specific services
	serviceConfig := kv.ServiceConfig{}

	// Create BoltDB store and K/V service
	svc.boltClient = bolt.NewClient(log.With(zap.String("service", "bolt")))
	svc.boltClient.Path = opts.boltPath
	if err := svc.boltClient.Open(ctx); err != nil {
		log.Error("Failed opening bolt", zap.Error(err))
		return nil, err
	}

	svc.store = bolt.NewKVStore(log.With(zap.String("service", "kvstore-bolt")), opts.boltPath)
	svc.store.WithDB(svc.boltClient.DB())
	svc.kvStore = svc.store
	svc.kvService = kv.NewService(log.With(zap.String("store", "kv")), svc.store, serviceConfig)

	// ensure migrator is run
	migrator, err := migration.NewMigrator(
		log.With(zap.String("service", "migrations")),
		svc.kvStore,
		all.Migrations[:]...,
	)
	if err != nil {
		log.Error("Failed to initialize kv migrator", zap.Error(err))
		return nil, err
	}

	// apply migrations to metadata store
	if err := migrator.Up(ctx); err != nil {
		log.Error("Failed to apply migrations", zap.Error(err))
		return nil, err
	}

	// other required services
	var (
		authSvc influxdb.AuthorizationService = svc.kvService
	)

	// Create Tenant service (orgs, buckets, )
	svc.tenantStore = tenant.NewStore(svc.kvStore)
	svc.ts = tenant.NewSystem(svc.tenantStore, log.With(zap.String("store", "new")), reg, metric.WithSuffix("new"))

	svc.meta = meta.NewClient(meta.NewConfig(), svc.kvStore)
	if err := svc.meta.Open(); err != nil {
		return nil, err
	}

	// DB/RP service
	svc.dbrpSvc = dbrp.NewService(ctx, svc.ts.BucketService, svc.kvStore)
	svc.bucketSvc = svc.ts.BucketService

	svc.enginePath = filepath.Join(filepath.Dir(svc.boltClient.Path), "engine")

	engine := storage.NewEngine(
		svc.enginePath,
		storage.NewConfig(),
		storage.WithMetaClient(svc.meta),
	)

	svc.ts.BucketService = storage.NewBucketService(svc.ts.BucketService, engine)
	// on-boarding service (influx setup)
	svc.onboardSvc = tenant.NewOnboardService(svc.ts, authSvc)

	return svc, nil
}

func openV1Meta(dir string) (*meta.Client, error) {
	cfg := meta.NewConfig()
	cfg.Dir = dir
	store := filestore.New(cfg.Dir, string(meta.BucketName), "meta.db")
	c := meta.NewClient(cfg, store)
	if err := c.Open(); err != nil {
		return nil, err
	}

	return c, nil
}

// influxDirV1 retrieves the influxdb directory.
func influxDirV1() (string, error) {
	var dir string
	// By default, store meta and data files in current users home directory
	u, err := user.Current()
	if err == nil {
		dir = u.HomeDir
	} else if home := os.Getenv("HOME"); home != "" {
		dir = home
	} else {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		dir = wd
	}
	dir = filepath.Join(dir, ".influxdb")

	return dir, nil
}

func rawDurationToTimeDuration(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}

	if dur, err := time.ParseDuration(raw); err == nil {
		return dur, nil
	}

	retention, err := options2.ParseSignedDuration(raw)
	if err != nil {
		return 0, err
	}

	const (
		day  = 24 * time.Hour
		week = 7 * day
	)

	var dur time.Duration
	for _, d := range retention.Values {
		if d.Magnitude < 0 {
			return 0, errors.New("must be greater than 0")
		}
		mag := time.Duration(d.Magnitude)
		switch d.Unit {
		case "w":
			dur += mag * week
		case "d":
			dur += mag * day
		case "m":
			dur += mag * time.Minute
		case "s":
			dur += mag * time.Second
		case "ms":
			dur += mag * time.Minute
		case "us":
			dur += mag * time.Microsecond
		case "ns":
			dur += mag * time.Nanosecond
		default:
			return 0, errors.New("duration must be week(w), day(d), hour(h), min(m), sec(s), millisec(ms), microsec(us), or nanosec(ns)")
		}
	}
	return dur, nil
}
