import sys
from gui.Diffie_Hellman_GUI import DiffieHellmanGUI
from PyQt5.QtWidgets import QApplication

def main():
    app = QApplication(sys.argv)
    window = DiffieHellmanGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()