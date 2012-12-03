#include "ExportDlg.h"

ExportDlg::ExportDlg(QWidget *parent) : QDialog(parent) {
    setupUi(this);
    connect(Check_Crypt,SIGNAL(stateChanged(int)),this,SLOT(OnCheckBoxesChanged()));

    OnCheckBoxesChanged();
}

void ExportDlg::OnCheckBoxesChanged() {
    Group_CryptFields->setEnabled(Check_Crypt->isChecked());
}

IExport::CryptedFields ExportDlg::flags() {
    IExport::CryptedFields flags = IExport::NONE;
    if(Check_Crypt->isChecked()) {
        if(Check_Username->isChecked()) {
            flags = IExport::CryptedFields(flags | IExport::USERNAME);
        }
        if(Check_Password->isChecked()) {
            flags = IExport::CryptedFields(flags | IExport::PASSWORD);
        }
        if(Check_Url->isChecked()) {
            flags = IExport::CryptedFields(flags | IExport::URL);
        }
        if(Check_Comment->isChecked()) {
            flags = IExport::CryptedFields(flags | IExport::COMMENT);
        }
        if(Check_Binary->isChecked()) {
            flags = IExport::CryptedFields(flags | IExport::BINARY);
        }
    }
    return flags;
}
