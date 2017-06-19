import time
import threading
import sys
import pyshark
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QWidget
from PyQt5.QtCore import QThread
from mainwindow import Ui_MainWindow
from PyQt5.QtCore import pyqtSignal
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QAction, QFileDialog, QApplication, QHeaderView


class ContentWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):

        self.setToolTip('This is a <b>Content Window</b> widget')
        self.setGeometry(150, 150, 500, 500)
        self.setWindowTitle('ContentWindow')
        self.layout = QtWidgets.QVBoxLayout(self)
        self.content_list = QtWidgets.QListWidget(self)
        self.hex_list = QtWidgets.QListWidget(self)
        self.layout.addWidget(self.content_list)
        self.layout.addWidget(self.hex_list)

    def trans_content(self, p_str1, p_str2):
        self.content_list.clear()
        self.hex_list.clear()
        self.content_list.addItems(p_str1)
        self.hex_list.addItems(p_str2)
        self.show()


class SharkThread(QThread):
    def __init__(self, main_window, pkt_list, fname):
        super().__init__()
        self.main_window = main_window
        self.pkt_list = pkt_list
        self.stop = False
        self.interface = ''
        self.filter_text = ''
        self.fname = fname

    def render(self, interface, filter_text):
        self.interface = interface
        self.filter_text = filter_text
        self.start()

    def run(self):
        # try:

        self.main_window.change_status.emit('running thread' + str(self.currentThreadId()))
        if self.interface == 'local':
            cap = pyshark.FileCapture(self.fname, display_filter=self.filter_text, keep_packets=False)

            for pkt in cap:
                temp_list=[str(pkt.number), str(pkt.sniff_time), str(pkt.ip.src), str(pkt.ip.dst),
                           str(pkt.highest_layer), str(pkt.length), str(pkt.layers)]
                self.pkt_list.append(pkt)
                self.main_window.push_summary.emit(temp_list)

        else:
            cap = pyshark.LiveCapture(interface=self.interface,bpf_filter=self.filter_text,)
            self.main_window.hide_filter.emit(True)
            for pkt in cap.sniff_continuously():
                if self.stop:
                    self.main_window.hide_filter.emit(False)
                    self.main_window.change_status.emit('thread finished')
                    break
                else:
                    temp_list = [str(pkt.number), str(pkt.sniff_time), str(pkt.ip.src), str(pkt.ip.dst),
                                 str(pkt.highest_layer), str(pkt.length), str(pkt.layers)]
                    self.pkt_list.append(pkt)
                    self.main_window.push_summary.emit(temp_list)

        self.main_window.change_status.emit('thread finished')
        # except Exception:
        #     self.main_window.label_2.setText('warning happened')

    def stop_thread(self):
        self.stop = True


class UI(QtWidgets.QMainWindow, Ui_MainWindow):

    push_summary = pyqtSignal(list, name='push_summary')
    hide_filter = pyqtSignal(bool, name='hide_filter')
    change_status = pyqtSignal(str, name='change_status')

    def __init__(self):
        super().__init__()
        self.initUI()

    def add_stopbutton(self, text):
        if self.stopbutton is None:
            if text != 'local':
                self.stopbutton = QtWidgets.QPushButton(self.centralWidget)
                self.horizontalLayout.addWidget(self.stopbutton)
                self.stopbutton.setText('Stop')
                self.stopbutton.clicked.connect(self.stop_sniff)
        elif text == 'local':
            self.stopbutton.hide()
        else:
            self.stopbutton.show()

    def push_entry(self, item_list):
        row = self.tableWidget.rowCount()
        self.tableWidget.insertRow(row)
        if len(self.tableWidget.selectedItems()) == 0:
            self.tableWidget.scrollToBottom()
        self.tableWidget.setItem(row, 0, QtWidgets.QTableWidgetItem(item_list[0]))
        self.tableWidget.setItem(row, 1, QtWidgets.QTableWidgetItem(item_list[1]))
        self.tableWidget.setItem(row, 2, QtWidgets.QTableWidgetItem(item_list[2]))
        self.tableWidget.setItem(row, 3, QtWidgets.QTableWidgetItem(item_list[3]))
        self.tableWidget.setItem(row, 4, QtWidgets.QTableWidgetItem(item_list[4]))
        self.tableWidget.setItem(row, 5, QtWidgets.QTableWidgetItem(item_list[5]))
        self.tableWidget.setItem(row, 6, QtWidgets.QTableWidgetItem(item_list[6]))

    def hide_filterbutton(self, flag):
        if flag == True:
            self.pushButton.hide()
        else:
            self.pushButton.show()

    def change_statusbar(self,string):
        self.statusBar.showMessage(string)

    def initUI(self):
        self.setupUi(self)
        self.pkt_list = []
        self.content_text_list = ''
        self.hex_text_list = ''
        self.tableWidget.cellClicked.connect(self.show_content)
        self.tableWidget.cellClicked.connect(self.show_hex)
        self.tableWidget.cellDoubleClicked.connect(self.show_content_widget)
        self.pushButton.clicked.connect(self.start_thread)
        self.thread = None
        self.stopbutton = None
        self.comboBox.currentTextChanged.connect(self.add_stopbutton)
        self.statusBar.showMessage('ready')
        self.push_summary.connect(self.push_entry)
        self.change_status.connect(self.change_statusbar)
        self.hide_filter.connect(self.hide_filterbutton)

        self.fname = 'mycapture.pcap'
        openFile = QAction(QIcon('folder.ico'), 'Open', self)
        openFile.setShortcut('Ctrl+O')
        openFile.setStatusTip('Open new File')
        openFile.triggered.connect(self.show_dialog)
        self.menuBar.setNativeMenuBar(False)
        file_menu = self.menuBar.addMenu('&File')
        file_menu.addAction(openFile)
        self.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tableWidget.setToolTip('This is a <b>Summary Table</b>')
        self.listWidget.setToolTip('This is a <b>Packet List</b>')
        self.listWidget_2.setToolTip('This is a <b>Hex content</b>')
        self.frame = ContentWidget()
        self.show()

    def show_dialog(self):
        fname = QFileDialog.getOpenFileName(self, 'Open file', '')

        if fname[0]:
            self.fname = fname[0]
            self.start_thread()

    def show_content_widget(self, row):
        self.show_content(row)
        self.show_hex(row)
        self.frame.trans_content(self.content_text_list, self.hex_text_list)

    def start_thread(self):
        if self.thread is not None and self.thread.isRunning():
            self.statusBar.showMessage('The thread is running')

        else:
            filter_text = self.lineEdit.text()
            interface = self.comboBox.currentText()
            self.pkt_list = []
            self.tableWidget.setRowCount(0)
            self.listWidget.clear()
            self.listWidget_2.clear()

            self.thread = SharkThread(self, self.pkt_list, self.fname)
            self.thread.render(interface=interface, filter_text=filter_text)

    def stop_sniff(self):
        if self.thread is not None:
            self.thread.stop_thread()

    def show_content(self, row):
        self.listWidget.clear()
        self.tableWidget.selectRow(row)
        packet = str(self.pkt_list[row])
        self.content_text_list = packet.split('\n')
        self.listWidget.addItems(self.content_text_list)

    def show_hex(self, row):
        self.tableWidget.selectRow(row)
        self.listWidget_2.clear()
        packet = self.pkt_list[row]

        self.hex_text_list = self.change_hex_content(packet).split('\n')
        self.listWidget_2.addItems(self.hex_text_list)

    def change_hex_content(self, packet):
        tmp_list = self.hex_content(packet)
        length = len(tmp_list)
        result = ''
        i = 0
        while(i < length):
            result += '%04x      ' % i
            for j in range(16):
                if i + j < length:
                    result += '{} '.format(tmp_list[i+j])
                else:
                    result += '     '
                if j % 15 == 7:
                    result += '     '
            result += '       '
            if i + 16 > length:
                result += '     '
                result += print_character(tmp_list[i:length])
            else:
                result += print_character(tmp_list[i:i+16])
            i += 16
            result += '\n'
        return result

    def hex_content(self, pkt):

        tmp_list = pkt.eth.dst.split(':')
        tmp_list += pkt.eth.src.split(':')
        tmp_list += [pkt.eth.type[6:8],pkt.eth.type[8:10]]
        tmp_list += [pkt.ip.version+str(int(int(pkt.ip.hdr_len)/int(pkt.ip.version)))]
        tmp_list += [pkt.ip.dsfield[8:10]]
        tmp_list += [hex(int(pkt.ip.len))[2:].zfill(4)[0:2],hex(int(pkt.ip.len))[2:].zfill(4)[2:]]
        tmp_list += [pkt.ip.id[6:8],pkt.ip.id[8:]]
        tmp_list += ['{}0'.format(pkt.ip.flags[-1]),'00']
        tmp_list += [hex(int(pkt.ip.ttl))[2:].zfill(2)]
        tmp_list += [hex(int(pkt.ip.proto))[2:].zfill(2)]
        tmp_list += [pkt.ip.checksum[-4:-2], pkt.ip.checksum[-2:]]
        tmp_list += [hex(int(i)).lstrip('0x').zfill(2) for i in (pkt.ip.src.split('.'))]
        tmp_list += [hex(int(i)).lstrip('0x').zfill(2) for i in (pkt.ip.dst.split('.'))]
        for i in range(len(tmp_list)):
            tmp_list[i]=tmp_list[i].upper()
        return tmp_list

    def keyPressEvent(self, e):

        if e.key() == Qt.Key_Escape:
            self.close()


def print_character(hex_list):
    char_string = ''
    for i in hex_list:
        num = int(i, 16)
        if num >= 127 or num <= 31:
            char_string += '.'
        else:
            char_string += ('%c' % num)
    return char_string


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = UI()
    sys.exit(app.exec_())



