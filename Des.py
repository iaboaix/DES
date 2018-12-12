# -*- coding:utf-8 -*-

"""
@project: Des
@file: Des.py
@author: dangzhiteng
@email: 642212607@qq.com
@date: 2018-12-12
"""

import sys
import base64
import os
from time import time
from pyDes import *
from PyQt5.QtCore import QPoint
from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtWidgets import QApplication, QWidget, QTabWidget, QHBoxLayout, \
                            QPushButton, QLineEdit, QFormLayout, QSizePolicy, \
                            QLabel, QVBoxLayout, QMessageBox, QFileDialog
import source_rc


class CryWin(QTabWidget):

    def __init__(self):
        super(CryWin, self).__init__()
        self.setWindowIcon(QIcon(QPixmap(':/pic/encry.png')))
        self.setWindowTitle('DES加解密')

        self.sourceLine = QLineEdit()
        self.encryption = QLineEdit()
        self.encryBtn = QPushButton('加密')
        self.encryBtn.setIcon(QIcon(QPixmap(':/pic/encry.png')))
        self.destLine = QLineEdit()
        self.decryBtn = QPushButton('解密')
        self.decryBtn.setIcon(QIcon(QPixmap(':/pic/decry.png')))
        self.resultLine = QLineEdit()

        self.layout1 = QFormLayout()
        self.layout1.addRow('原始字符串:', self.sourceLine)
        self.layout1.addRow('密钥:', self.encryption)
        self.layout1.addRow('', self.encryBtn)
        self.layout1.addRow('加密字符串:', self.destLine)
        self.layout1.addRow('', self.decryBtn)
        self.layout1.addRow('解密字符串:', self.resultLine)

        self.filePathLine = QLineEdit()
        self.loadFileBtn = QPushButton('加载文件')
        self.encryFileBtn = QPushButton('加密')
        self.encryFileBtn.setIcon(QIcon(QPixmap(':/pic/encry.png')))
        self.decryFileBtn = QPushButton('解密')
        self.decryFileBtn.setIcon(QIcon(QPixmap(':/pic/decry.png')))
        self.encryFileBtn.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.decryFileBtn.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.labelStatus = QLabel('运行状态:')
        self.labelStatus.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Minimum)
        self.status = QLabel('点击进行 加/解 密...')
        self.status.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        self.labelStatus.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.status.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.fileEncryption = QLineEdit()
        self.fileEncryption.setPlaceholderText('在此处输入密钥')

        self.layout2_1 = QHBoxLayout()
        self.layout2_1.addWidget(self.filePathLine)
        self.layout2_1.addWidget(self.loadFileBtn)

        self.layout2_2 = QHBoxLayout()
        self.layout2_2.addWidget(self.encryFileBtn)
        self.layout2_2.addWidget(self.decryFileBtn)
        
        self.layout2_3 = QHBoxLayout()
        self.layout2_3.addWidget(self.labelStatus)
        self.layout2_3.addWidget(self.status)

        self.layout2 = QVBoxLayout()
        self.layout2.addLayout(self.layout2_1)
        self.layout2.addWidget(self.fileEncryption)
        self.layout2.addLayout(self.layout2_2)
        self.layout2.addLayout(self.layout2_3)

        self.widget1 = QWidget()
        self.widget1.setLayout(self.layout1)    
        self.widget2 = QWidget()
        self.widget2.setLayout(self.layout2)  

        self.addTab(self.widget1, '加密字符串')
        self.addTab(self.widget2, '加密文件')

        self.encryBtn.clicked.connect(self.encrydata)
        self.decryBtn.clicked.connect(self.decrydata)   
        self.loadFileBtn.clicked.connect(self.loadFile)
        self.encryFileBtn.clicked.connect(self.encryFile)
        self.decryFileBtn.clicked.connect(self.decryFile)  

    def encrydata(self):
        if len(self.encryption.text()) != 8:
            QMessageBox.warning(self, 'warning', '请输入正确的密钥！')
            return
        print('加密过程:')
        mydes = des(bytes(self.encryption.text(), encoding='utf-8'),
                    CBC, b"\0\0\0\0\0\0\0\0", padmode=PAD_PKCS5)
        print('data:', self.sourceLine.text())
        print('key:', self.encryption.text())
        result = base64.b64encode(mydes.encrypt(self.sourceLine.text()))
        print('result:', result.decode())
        self.destLine.setText(result.decode())

    def decrydata(self):
        if len(self.encryption.text()) != 8:
            QMessageBox.warning(self, 'warning', '请输入正确的密钥！')
            return
        print('解密过程:')
        mydes = des(bytes(self.encryption.text(), encoding='utf8'), 
                    CBC, "\0\0\0\0\0\0\0\0", padmode=PAD_PKCS5)
        print('data:', self.destLine.text())
        print('key:', self.encryption.text())
        result = mydes.decrypt(base64.b64decode(self.destLine.text().encode()))
        print('result:', result.decode())
        self.resultLine.setText(result.decode())    

    def loadFile(self):
        filePath, ok = QFileDialog.getOpenFileUrl(self, '选择要加密的文件',\
                                                  '~/Desktop', 'All Files(*)')
        if ok:
            self.filePathLine.setText(filePath.toLocalFile())

    def encryFile(self):
        if len(self.fileEncryption.text()) != 8:
            QMessageBox.warning(self, 'warning', '请输入正确的密钥！')
            return
        stime = time()
        self.status.setText('正在进行加密,请等待...')
        file = open(self.filePathLine.text(), 'rb')
        data = file.read()
        file.close()
        mydes = des(bytes(self.fileEncryption.text(), encoding='utf8'))
        file = open(os.path.split(self.filePathLine.text())[-1] + '.enc', 'wb')
        file.write(mydes.encrypt(data, ' '))
        file.close()
        etime = time()
        self.status.setText('加密完成,用时{}s'.format(str(round(etime - stime, 2))))

    def decryFile(self):
        if len(self.fileEncryption.text()) != 8:
            QMessageBox.warning(self, 'warning', '请输入正确的密钥！')
            return
        stime = time()
        fileName = self.filePathLine.text()
        if fileName.endswith('.enc') is not True:
            QMessageBox.warning(self, 'warning', '只能对已加密文件进行解密！')
            return
        self.status.setText('正在进行解密,请等待...')
        file = open(fileName, 'rb')
        data = file.read()
        file.close()
        mydes = des(bytes(self.fileEncryption.text(), encoding='utf8'))
        file = open(os.path.split(self.filePathLine.text())[-1] + '.dec', 'wb')
        file.write(mydes.decrypt(data, ' '))
        etime = time()
        self.status.setText('解密完成,用时{}s'.format(str(round(etime - stime, 2))))

    

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = CryWin()
    win.show()
    sys.exit(app.exec_())

