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
            print(f"O arquivo de configuração '{self.config_file_path}' não foi encontrado.")
            return {}

    def get_value(self, section, parameter_name):

        value = self.config_data.get(section, {}).get(parameter_name)
        
        if value is None:
            raise ValueError(f"Configuration is not defined - Section: {section}  | Param: {parameter_name}")

        return value
    
# Exemplo de uso:
config = Config('rdptrio/config/rdpVersion.yaml')

# Especificando a seção 'teste' e o nome do parâmetro 'RDP_VERSION_4'
test_rdp_version_4 = config.get_value('versions', 'RDP_VERSION_5_PLUS')

# Imprimindo o valor do parâmetro 'RDP_VERSION_4' sob a seção 'teste'
print(f"Valor de 'RDP_VERSION_4' sob 'teste': {test_rdp_version_4}")

