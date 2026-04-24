import logging
import subprocess
import time
import os
from threading import Lock
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime
import gc
import ExternalIntegrationsConnector as ext_db

logging.basicConfig(
    filename="/var/log/scheduler_log.log",
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

job_lock = Lock()


def read_secret(secret_path):
    """Read a Docker secret from file"""
    try:
        with open(secret_path, 'r') as f:
            return f.read().strip()
    except Exception as e:
        logger.error(f"Error reading secret {secret_path}: {e}")
        return None


def initialize_external_integration_tables():
    """Create external integration tables at startup"""
    try:
        logger.info("Initializing external integration tables...")

        host = os.environ.get('DATABASE_HOST', 'appdb')
        port = os.environ.get('DATABASE_PORT', '5432')
        database = read_secret('/run/secrets/postgres_db')
        user = read_secret('/run/secrets/postgres_user')
        password = read_secret('/run/secrets/postgres_password')

        if not database or not user or not password:
            logger.error("Missing database credentials, skipping table creation")
            return

        ext_db.check_create_all_external_integration_tables(
            host, port, user, password, database
        )

        logger.info("External integration tables initialized successfully")

    except Exception as e:
        logger.error(f"Error initializing external integration tables: {e}")


def run_bash_script(script_path: str) -> None:
    allowed_dir = "/usr/src/app/scripts/"
    real_path = os.path.realpath(script_path)

    if not real_path.startswith(os.path.realpath(allowed_dir)):
        logger.error(f"Invalid script path: {script_path}")
        return

    if not os.path.exists(real_path):
        logger.error(f"Script does not exist: {script_path}")
        return

    try:
        logger.info(f"Starting execution of {script_path} at {datetime.now()}")
        subprocess.run(["bash", real_path], shell=False, check=True)
        logger.info(f"Successfully executed {script_path} at {datetime.now()}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing {script_path}: {e} at {datetime.now()}")
    except Exception as e:
        logger.error(f"Unexpected error executing {script_path}: {e} at {datetime.now()}")
    finally:
        logger.info(f"Finished execution of {script_path} at {datetime.now()}")
        gc.collect()


def full_sync() -> None:
    with job_lock:
        logger.info("Starting full sync at " + str(datetime.now()))

        print("Running job 1 (refreshTables) at " + str(datetime.now()))
        run_bash_script("/usr/src/app/scripts/refreshTables.sh")

        print("Running job 2 (activeVulnsSync) at " + str(datetime.now()))
        run_bash_script("/usr/src/app/scripts/activeVulnsSync.sh")

        print("Running job 3 (difTables) at " + str(datetime.now()))
        run_bash_script("/usr/src/app/scripts/difTables.sh")

        print("Running job (qualysSync) at " + str(datetime.now()))
        run_bash_script("/usr/src/app/scripts/QualysSync.sh")

        print("Running job (falconSync) at " + str(datetime.now()))
        run_bash_script("/usr/src/app/scripts/FalconSync.sh")

        print("Running job (snowSync) at " + str(datetime.now()))
        run_bash_script("/usr/src/app/scripts/SnowSync.sh")

        print("Running job (mdeSync) at " + str(datetime.now()))
        run_bash_script("/usr/src/app/scripts/MDESync.sh")

        print("Running job (automoxSync) at " + str(datetime.now()))
        run_bash_script("/usr/src/app/scripts/AutomoxSync.sh")

        print("Running job (wizSync) at " + str(datetime.now()))
        run_bash_script("/usr/src/app/scripts/WizSync.sh")

        print("Running job (wizSync2) at " + str(datetime.now()))
        run_bash_script("/usr/src/app/scripts/WizSync2.sh")

        print("Running job (sentinelOneSync) at " + str(datetime.now()))
        run_bash_script("/usr/src/app/scripts/SentinelOneSync.sh")

        print("Running job (trendmicroSync) at " + str(datetime.now()))
        run_bash_script("/usr/src/app/scripts/TrendmicroSync.sh")

        rapid7_key_path = "/run/secrets/rapid7_api_key"
        if os.path.exists(rapid7_key_path):
            print("Running job (rapid7Sync) at " + str(datetime.now()))
            run_bash_script("/usr/src/app/scripts/Rapid7Sync.sh")
        else:
            logger.info("Skipping Rapid7 sync: missing rapid7_api_key secret")

        tenable_access_path = "/run/secrets/tenable_access_key"
        tenable_secret_path = "/run/secrets/tenable_secret_key"
        if os.path.exists(tenable_access_path) and os.path.exists(tenable_secret_path):
            print("Running job 5 (tenableSync) at " + str(datetime.now()))
            run_bash_script("/usr/src/app/scripts/tenableSync.sh")
        else:
            logger.info("Skipping Tenable sync: missing tenable_access_key/tenable_secret_key secrets")

        external_enabled = os.environ.get("EXTERNAL_DATA_ENABLED", "false").lower() == "true"
        vulncheck_enabled = os.environ.get("VULNCHECK_ENABLED", "false").lower() == "true"

        if external_enabled or vulncheck_enabled:
            print("Running job 4 (externalDataSync) at " + str(datetime.now()))
            run_bash_script("/usr/src/app/scripts/externalDataSync.sh")

        logger.info("Completed full sync at " + str(datetime.now()))


if __name__ == "__main__":
    sync_interval = int(os.environ.get("SYNC_INTERVAL", "6"))
    logger.info(f"Configured sync interval: {sync_interval} hours")

    logger.info("=" * 70)
    logger.info("INITIALIZING EXTERNAL INTEGRATION TABLES")
    logger.info("=" * 70)
    initialize_external_integration_tables()
    logger.info("=" * 70)

    logger.info("Starting initial sync process")

    initial_command = ["/usr/local/bin/python", "/usr/src/app/scripts/VickyTopiaReportCLI.py", "--allreports"]
    logger.info("Starting initial Vicarius data sync")
    try:
        with open("/var/log/initialsync.log", "a") as log_file:
            subprocess.run(
                initial_command,
                shell=False,
                check=True,
                stdout=log_file,
                stderr=subprocess.STDOUT,
            )
        logger.info("Initial Vicarius data sync completed successfully")
    except subprocess.CalledProcessError as e:
        logger.error(f"Initial Vicarius data sync failed: {e}")

    logger.info("Starting initial Qualys sync")
    try:
        run_bash_script("/usr/src/app/scripts/QualysSync.sh")
        logger.info("Initial Qualys sync completed successfully")
    except Exception as e:
        logger.error(f"Initial Qualys sync failed: {e}")

    logger.info("Starting initial Falcon sync")
    try:
        run_bash_script("/usr/src/app/scripts/FalconSync.sh")
        logger.info("Initial Falcon sync completed successfully")
    except Exception as e:
        logger.error(f"Initial Falcon sync failed: {e}")

    logger.info("Starting initial Snow sync")
    try:
        run_bash_script("/usr/src/app/scripts/SnowSync.sh")
        logger.info("Initial Snow sync completed successfully")
    except Exception as e:
        logger.error(f"Initial Snow sync failed: {e}")

    logger.info("Starting initial MDE sync")
    try:
        run_bash_script("/usr/src/app/scripts/MDESync.sh")
        logger.info("Initial MDE sync completed successfully")
    except Exception as e:
        logger.error(f"Initial MDE sync failed: {e}")

    logger.info("Starting initial Automox sync")
    try:
        run_bash_script("/usr/src/app/scripts/AutomoxSync.sh")
        logger.info("Initial Automox sync completed successfully")
    except Exception as e:
        logger.error(f"Initial Automox sync failed: {e}")

    logger.info("Starting initial Wiz sync")
    try:
        run_bash_script("/usr/src/app/scripts/WizSync.sh")
        logger.info("Initial Wiz sync completed successfully")
    except Exception as e:
        logger.error(f"Initial Wiz sync failed: {e}")

    logger.info("Starting initial Wiz sync 2")
    try:
        run_bash_script("/usr/src/app/scripts/WizSync2.sh")
        logger.info("Initial Wiz sync 2 completed successfully")
    except Exception as e:
        logger.error(f"Initial Wiz sync 2 failed: {e}")

    logger.info("Starting initial SentinelOne sync")
    try:
        run_bash_script("/usr/src/app/scripts/SentinelOneSync.sh")
        logger.info("Initial SentinelOne sync completed successfully")
    except Exception as e:
        logger.error(f"Initial SentinelOne sync failed: {e}")

    logger.info("Starting initial TrendMicro sync")
    try:
        run_bash_script("/usr/src/app/scripts/TrendmicroSync.sh")
        logger.info("Initial TrendMicro sync completed successfully")
    except Exception as e:
        logger.error(f"Initial TrendMicro sync failed: {e}")

    rapid7_key_path = "/run/secrets/rapid7_api_key"
    if os.path.exists(rapid7_key_path):
        logger.info("Starting initial Rapid7 sync")
        try:
            run_bash_script("/usr/src/app/scripts/Rapid7Sync.sh")
            logger.info("Initial Rapid7 sync completed successfully")
        except Exception as e:
            logger.error(f"Initial Rapid7 sync failed: {e}")
    else:
        logger.info("Skipping initial Rapid7 sync: missing rapid7_api_key secret")

    external_enabled = os.environ.get("EXTERNAL_DATA_ENABLED", "false").lower() == "true"
    vulncheck_enabled = os.environ.get("VULNCHECK_ENABLED", "false").lower() == "true"

    if external_enabled or vulncheck_enabled:
        logger.info("Starting initial external data sync")
        try:
            subprocess.run(
                ["/usr/local/bin/python", "/usr/src/app/scripts/updateExternalScore.py"],
                shell=False,
                check=True,
            )
            logger.info("Initial external data sync completed successfully")
        except subprocess.CalledProcessError as e:
            logger.error(f"Initial external data sync failed: {e}")

    tenable_access_path = "/run/secrets/tenable_access_key"
    tenable_secret_path = "/run/secrets/tenable_secret_key"
    if os.path.exists(tenable_access_path) and os.path.exists(tenable_secret_path):
        logger.info("Starting initial Tenable sync")
        try:
            run_bash_script("/usr/src/app/scripts/tenableSync.sh")
            logger.info("Initial Tenable sync completed successfully")
        except Exception as e:
            logger.error(f"Initial Tenable sync failed: {e}")
    else:
        logger.info("Skipping initial Tenable sync: missing tenable secrets")

    logger.info("Initial sync process completed")

    executors = {"default": ThreadPoolExecutor(max_workers=1)}
    scheduler = BackgroundScheduler(executors=executors)

    scheduler.add_job(
        full_sync,
        trigger=IntervalTrigger(hours=sync_interval),
        id="full_sync",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        misfire_grace_time=1,
    )

    logger.info("Starting Scheduler with " + str(sync_interval) + " hour interval at " + str(datetime.now()))
    scheduler.start()

    try:
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
        logger.info("Scheduler shut down at " + str(datetime.now()))
