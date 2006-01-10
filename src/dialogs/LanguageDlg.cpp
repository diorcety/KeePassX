/***************************************************************************
 *   Copyright (C) 2005 by Tarek Saidi   *
 *   mail@tarek-saidi.de   *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/
#include "main.h"
#include "LanguageDlg.h"
#include <qtranslator.h>
#include <qdir.h>
#include <qstringlist.h>
#include <q3listview.h>
#include <qmessagebox.h>
//Added by qt3to4:
#include <QShowEvent>
#include <iostream>
using namespace std;

const char* infostrings[]={
QT_TRANSLATE_NOOP("_INFO","$TRANSL_AUTHOR"),
QT_TRANSLATE_NOOP("_INFO","$TRANSL_AUTHOR_CONTACT"),
QT_TRANSLATE_NOOP("_INFO","$TRANSL_LANGUAGE"),
QT_TRANSLATE_NOOP("_INFO","$TRANSL_VERSION")};
const char* msg[]={QT_TRANSLATE_NOOP("_MSG","Die Änderung der Sprache wird erst nach einem Neustart von Keepass wirksam."),
		   QT_TRANSLATE_NOOP("_MSG","OK"),
		   QT_TRANSLATE_NOOP("_MSG","Hinweis")};

CLanguageDlg::CLanguageDlg(QWidget* parent, const char* name, Qt::WFlags fl)
: QDialog(parent,name,fl)
{
setupUi(this);

createBanner(Banner,Icon_I18n32x32,trUtf8("Spracheinstellungen"));

Q3ListViewItem* item;
QString& config_lang=config.Language;
QStringList files;

QString langdir=AppDir+"/../share/keepass/i18n/";
QDir dir(langdir);
if(dir.exists()){
files=dir.entryList("*.qm",QDir::Files);
}

List->insertItem(item=new Q3ListViewItem(List,"","Deutsch","-","-"));
if(config_lang=="_DEUTSCH_")item->setPixmap(0,*Icon_Ok16x16);
pItems.push_back(item);
filenames.push_back("_DEUTSCH_");


for(int i=0;i<files.count();i++){
QTranslator translator;
 if(!translator.load(langdir+files[i])){
  QMessageBox::warning(this,tr("Warnung"),tr("Die Datei '%1' konnte nicht geladen werden.").arg(files[i]),tr("OK"),0,0,2,1);
  continue;}
List->insertItem(item=new Q3ListViewItem(List,"",translator.translate("_INFO","$TRANSL_LANGUAGE")
				       ,translator.translate("_INFO","$TRANSL_VERSION")
				       ,translator.translate("_INFO","$TRANSL_AUTHOR")));
if(config_lang==files[i])item->setPixmap(0,*Icon_Ok16x16);
pItems.push_back(item);
filenames.push_back(files[i]);
}
}

CLanguageDlg::~CLanguageDlg()
{
}

void CLanguageDlg::showEvent(QShowEvent *event){
if(event->spontaneous()==false){
List->setColumnWidth(0,20);
int width=(List->width()-4-20)/3;
List->setColumnWidth(1,width);
List->setColumnWidth(2,width);
List->setColumnWidth(3,width);
}
}

void CLanguageDlg::OnItemRightClick(Q3ListViewItem* item)
{
//CTX-MENU

}

void CLanguageDlg::OnItemDoubleClicked(Q3ListViewItem* item) // == Slot für Button "wählen"
{
int i;
QString langdir=AppDir+"/../share/keepass/i18n/";

for(i=0;i<pItems.size();i++){
 if(item==pItems[i])break;
 if(i==pItems.size()-1){
	qWarning(QString("unexpected error in %1, line %2").arg(__FILE__).arg(__LINE__)+"\n");
	exit(-1);}
}
if(filenames[i]!="_DEUTSCH_"){
QTranslator translator;
if(!translator.load(langdir+filenames[i])){
 QMessageBox::warning(this,tr("Warnung"),tr("Die Datei '%1' konnte nicht geladen werden.").arg(filenames[i]),tr("OK"),0,0,2,1);
 return;
}
QMessageBox::information(this,translator.translate("_MSG",msg[2])
			     ,translator.translate("_MSG",msg[0])
			     ,translator.translate("_MSG",msg[1])
			     ,0,0,0);
}
else QMessageBox::information(this,QString::fromUtf8(msg[2]),QString::fromUtf8(msg[0]),QString::fromUtf8(msg[1]),0,0,2,1);
config.Language=filenames[i];

for(int j=0;j<pItems.size();j++){
if(j==i)pItems[j]->setPixmap(0,*Icon_Ok16x16);
else pItems[j]->setPixmap(0,0);}

List->setColumnWidth(0,20);
int width=(List->width()-4-20)/3;
List->setColumnWidth(1,width);
List->setColumnWidth(2,width);
List->setColumnWidth(3,width);

}

void CLanguageDlg::OnApplyButtonClicked()
{
Q3ListViewItem* item=List->selectedItem();
if(item)OnItemDoubleClicked(item);
else QMessageBox::information(this,tr("Hinweis"),trUtf8("Es ist keine Übersetzung aufsgewählt."),tr("OK"),0,0,2,1);
}

void CLanguageDlg::OnButtonCloseClicked()
{
done(0);
}





/*$SPECIALIZATION$*/


