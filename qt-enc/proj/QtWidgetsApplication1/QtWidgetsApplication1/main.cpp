#include <QApplication>
#include <QWidget>
#include <QPushButton>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QFileDialog>
#include <QStackedWidget>
#include <QMessageBox>
#include "aes.h"
#include "rsa.h"

class FileException : public std::exception {
public:
    explicit FileException(const QString& message) : msg(message) {}

    const char* what() const noexcept override {
        return msg.toStdString().c_str();
    }

private:
    QString msg;
};



class EncryptApp : public QWidget {
    Q_OBJECT

public:
    EncryptApp(QWidget* parent = nullptr);

private slots:
    void encryptText();
    void saveToFile();
    void setAlgorithm(bool isRSA);

private:
    QTextEdit* inputTextEdit;
    QTextEdit* outputTextEdit;
    QPushButton* rsaButton;
    QPushButton* aesButton;
    QPushButton* encryptButton;
    QPushButton* saveButton;
    bool useRSA;
};

EncryptApp::EncryptApp(QWidget* parent)
    : QWidget(parent), useRSA(true) {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);

    QLabel* headerLabel = new QLabel("Cloak", this);
    headerLabel->setAlignment(Qt::AlignCenter);
    headerLabel->setStyleSheet("font-size: 24px; font-weight: bold; margin-bottom: 20px;");

    inputTextEdit = new QTextEdit(this);
    outputTextEdit = new QTextEdit(this);
    outputTextEdit->setReadOnly(true);

    QHBoxLayout* algorithmLayout = new QHBoxLayout();
    rsaButton = new QPushButton("Use RSA", this);
    aesButton = new QPushButton("Use AES", this);
    rsaButton->setCheckable(true);
    aesButton->setCheckable(true);
    rsaButton->setChecked(true); // RSA is the default
    connect(rsaButton, &QPushButton::clicked, [this]() { setAlgorithm(true); });
    connect(aesButton, &QPushButton::clicked, [this]() { setAlgorithm(false); });

    algorithmLayout->addWidget(rsaButton);
    algorithmLayout->addWidget(aesButton);

    QHBoxLayout* actionLayout = new QHBoxLayout();
    encryptButton = new QPushButton("Encrypt", this);
    saveButton = new QPushButton("Save to File", this);
    actionLayout->addWidget(encryptButton);
    actionLayout->addWidget(saveButton);

    mainLayout->addWidget(headerLabel);
    mainLayout->addWidget(new QLabel("Input Text:", this));
    mainLayout->addWidget(inputTextEdit);
    mainLayout->addLayout(algorithmLayout);
    mainLayout->addLayout(actionLayout);
    mainLayout->addWidget(new QLabel("Encrypted Text:", this));
    mainLayout->addWidget(outputTextEdit);

    connect(encryptButton, &QPushButton::clicked, this, &EncryptApp::encryptText);
    connect(saveButton, &QPushButton::clicked, this, &EncryptApp::saveToFile);

    setLayout(mainLayout);
    setWindowTitle("EncryptApp");

    setStyleSheet(
        "QWidget {"
        "    background-color: #262525;"
        "    color: white;"
        "}"
        "QPushButton {"
        "    background-color: #4a4444;"
        "    color: white;"
        "    border: none;"
        "    padding: 10px 20px;"
        "    text-align: center;"
        "    text-decoration: none;"
        "    display: inline-block;"
        "    font-size: 14px;"
        "    margin: 4px 2px;"
        "    cursor: pointer;"
        "    border-radius: 4px;"
        "}"
        "QPushButton:checked {"
        "    background-color: #6200ea;"
        "    color: white;"
        "}"
        "QPushButton:unchecked {"
        "    background-color: #4a4444;"
        "    color: #6200ea;"
        "}"
        "QPushButton:hover {"
        "    background-color: #6200ea;"
        "}"
        "QTextEdit {"
        "    background-color: #333333;"
        "    color: white;"
        "    border: 1px solid #111;"
        "    padding: 5px;"
        "    font-size: 14px;"
        "}"
        "QLabel {"
        "    font-size: 16px;"
        "    font-weight: bold;"
        "    margin: 10px 0;"
        "}"
    );
}

void EncryptApp::setAlgorithm(bool isRSA) {
    useRSA = isRSA;
    rsaButton->setChecked(isRSA);
    aesButton->setChecked(!isRSA);
}

void EncryptApp::encryptText() {
    QString inputText = inputTextEdit->toPlainText();
    QString outputText;
    if (useRSA) {
        RSA rsa;
        std::vector<int> encryptedMessage = rsa.encryptString(inputText.toStdString());
        for (int c : encryptedMessage) {
            outputText += QString::number(c) + " ";
        }
    }
    else {
        std::vector<uint8_t> key = {
            0x2b, 0x7e, 0x15, 0x16,
            0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x09, 0xcf,
            0x4f, 0x3c, 0xe2, 0xb8
        };
        AES128 aes(key);
        std::vector<uint8_t> encryptedMessage = aes.EncryptMessage(inputText.toStdString());
        for (uint8_t byte : encryptedMessage) {
            outputText += QString("%1 ").arg(byte, 2, 16, QChar('0'));
        }
    }
    outputTextEdit->setText(outputText);
}


void EncryptApp::saveToFile() {
    try {
        QString fileName = QFileDialog::getSaveFileName(this, "Save File", "", "Text Files (*.txt);;All Files (*)");
        if (fileName.isEmpty()) {
            throw FileException("No file name specified.");
        }

        QFile file(fileName);
        if (!file.open(QFile::WriteOnly | QFile::Text)) {
            throw FileException("Unable to open file for writing.");
        }

        QTextStream out(&file);
        out << outputTextEdit->toPlainText();
        file.close();
    }
    catch (const FileException& e) {
        QMessageBox::critical(this, "Error", e.what());
    }
}

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    EncryptApp window;
    window.resize(600, 400);
    window.show();
    return app.exec();
}

#include "main.moc"


