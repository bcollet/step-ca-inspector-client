import os
import sys

import yaml


class config:
    @classmethod
    def __init__(self):
        for config_path in (
            os.path.expanduser("~/.config/step-ca-inspector"),
            os.environ.get("STEP_CA_INSPECTOR_CONF"),
        ):
            if config_path is None:
                continue
            try:
                with open(os.path.join(config_path, "config.yaml")) as ymlfile:
                    cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)
                    break
            except OSError:
                pass
        else:
            print("No configuration file found")
            sys.exit(1)

        for k, v in cfg.items():
            setattr(self, k, v)

        for setting in ["url"]:
            if not hasattr(self, setting):
                # FIXME: Raise instead
                print(f"Mandatory setting {setting} is not configured.")
                sys.exit(1)
