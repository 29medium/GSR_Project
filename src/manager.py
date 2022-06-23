import json
from threading import Lock
from encrypt import DH, EncryptError, AuthenticationEncryptError
from socket import *
import sys

# classe responsável pela entidade manager
class Manager:
    # inicialização da classe Manager
    def __init__(self):
        self.HOST = "localhost"
        self.PORT = 65432
        self.conn = None

        self.user_name = None
        self.password = None
        self.proxy_password = None
        self.shared_key = None

        self.requests = set()

    # função que imprime o menu de opções e recebe opção de input
    def readOption():
        result = -1

        while result<=0 or result>3:
            print("\n----------------------------------")
            print(" 1 | Mostrar resultados")
            print(" 2 | Executar pedidos")
            print(" 3 | Executar pedidos predefinidos")
            print("----------------------------------")

            try:
                result = int(input(" Escolha uma opção >> "))
            except ValueError:
                result = -1
        
        return result

    # função que recebe os acks do proxy
    def receiveAck(self, numAck):
        for i in range(0,numAck):
            ack = DH.recv(self.conn, self.shared_key)
            self.requests.add(ack.split(",")[1])

    # função que lida com os pedidos do administrador e envia-os ao proxy
    def menu(self):
        while True:
            option = Manager.readOption()

            # pedido response
            if option==1:
                print("\n ID Operações disponivéis:", end =" ")
                for req in self.requests:
                    print(str(req), end =" ")
                oid = input("\n Inserir pedido >> ")
                msg = "response," + oid

                DH.send(msg, self.conn, self.shared_key)
                data = DH.recv(self.conn, self.shared_key)

                print("\n" + data)
            
            # pedido get ou get_next
            elif option==2:
                type = input(" Inserir tipo (get/get_next) >> ")
                if(type in ["get","get_next"]):
                    ip = input(" Inserir host >> ")
                    community = input(" Inserir community string >> ")
                    oids = input(" Inserir oids separados por virgula >> ")

                    msg = type + "," + ip + "," + community + "," + oids
                    DH.send(msg, self.conn, self.shared_key)
                    
                    self.receiveAck(len(oids.split(",")))

                    print("\nPedido efetuado")
                else:
                    print("\nPedido não efetuado. Tipo incorreto")
            
            # pedidos predefinidos, para efeitos de teste
            if option==3:
                msg = "get,192.168.1.68,public,1.3.6.1.2.1.1.1.0"
                DH.send(msg, self.conn, self.shared_key)
                self.receiveAck(1)
                
                msg = "get_next,192.168.1.68,public,1.3.6.1.2.1.1"
                DH.send(msg, self.conn, self.shared_key)
                self.receiveAck(1)

                print("\nPedidos efetuados")

    # função corrida ao iniciar a classe Manager
    def run(self):
        args = sys.argv
        argc = len(args) - 1

        if argc != 2:
            print("Numero de argumentos errado. Esperado 2, Obtido " + str(argc))
            return

        # dá parse e guarda ficheiro com password do proxy 
        self.user_name = args[1]
        self.password = args[2]
        self.proxy_password = json.load(open("../files/proxy.json"))['proxy']

        try:
            # socket conecta-se ao proxy
            self.conn = socket()
            self.conn.connect((self.HOST, self.PORT))

            # cria shared_key
            self.shared_key = DH.connection(self.conn)

            # autentica o proxy
            DH.authentication_manager(self.conn, self.user_name, self.password, self.proxy_password, self.shared_key)

            self.menu()

        except AuthenticationEncryptError:
            print("Erro na autenticação")
            self.conn.close()

        except EncryptError:
            print("\nErro a estabelecer ligação com o proxy")
            self.conn.close()

        except ConnectionRefusedError:
            print("\nProxy indiponível")

        except KeyboardInterrupt:
            print("\nConexão terminada")
        
        except IndexError:
            print("\nConexão interrompida")
            pass

manager = Manager()
manager.run()