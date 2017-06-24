

from cloud_admin.services.services import EucaComponentService, SHOW_COMPONENTS


class EucaWalrusBackendService(EucaComponentService):

    def show(self, print_table=True):
        return SHOW_COMPONENTS(self.connection, self, print_table)
