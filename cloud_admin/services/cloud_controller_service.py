
from cloud_admin.services.services import EucaComponentService, SHOW_COMPONENTS


class EucaCloudControllerService(EucaComponentService):

    def show(self, print_table=True):
        return SHOW_COMPONENTS(connection=self.connection, components=self, print_table=print_table)
