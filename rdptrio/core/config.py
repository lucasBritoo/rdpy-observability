import yaml

class Config:
    def __init__(self, config_file_path):
        self.config_file_path = config_file_path
        self.config_data = self.load_config()

    def load_config(self):
        try:
            with open(self.config_file_path, 'r') as config_file:
                return yaml.safe_load(config_file)
        except FileNotFoundError:
            print(f"Configuration file'{self.config_file_path}' does not found.")
            return {}

    def get_value(self, section, parameter_name):

        value = self.config_data.get(section, {}).get(parameter_name)
        
        if value is None:
            raise ValueError(f"Configuration is not defined - Section: {section}  | Param: {parameter_name}")

        return value

# # Exemplo de uso:
# config = Config('rdptrio/config/rdpVersion.yaml')
# rdp_version_4 = config.get_version('RDP_VERSION_4')
# rdp_version_5_plus = config.get_version('RDP_VERSION_5_PLUS')

# print(f"RDP Version 4: {rdp_version_4}")
# print(f"RDP Version 5 and above: {rdp_version_5_plus}")

