#ifndef EXPORTDLG_H
#define EXPORTDLG_H

#include "ui_ExportDlg.h"
#include "export/Export.h"

class ExportDlg : public QDialog, private Ui_ExportDlg
{
    Q_OBJECT
    
public:
    ExportDlg(QWidget *parent = 0);
    IExport::CryptedFields flags();

private slots:
    void OnCheckBoxesChanged();
};

#endif // EXPORTDLG_H
