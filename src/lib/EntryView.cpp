/***************************************************************************
 *   Copyright (C) 2005-2006 by Tarek Saidi                                *
 *   tarek.saidi@arcor.de                                                  *
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


#include <QDragEnterEvent>
#include <QDragMoveEvent>
#include <QDragLeaveEvent>
#include <QDropEvent>
#include <QMouseEvent>
#include <QHeaderView>
#include <QTime>
#include <QApplication>
#include <QPainter>
#include <QPair>
#include "main.h"
#include "PwmConfig.h"
#include "EntryView.h"



KeepassEntryView::KeepassEntryView(QWidget* parent):QTreeWidget(parent){
AutoResizeColumns=true;
IsSearchGroup=false;
int sum=0;
for(int i=0;i<NUM_COLUMNS;i++)
	sum+=config.ColumnSizes[i];
for(int i=0;i<NUM_COLUMNS;i++)
	ColumnSizes << (float)config.ColumnSizes[i]/(float)sum;

CurrentGroup=0;
updateColumns();
header()->setResizeMode(QHeaderView::Interactive);
header()->setStretchLastSection(false);
connect(header(),SIGNAL(sectionResized(int,int,int)),this,SLOT(OnColumnResized(int,int,int)));
ContextMenu=new QMenu(this);
setAlternatingRowColors(config.AlternatingRowColors);


}

KeepassEntryView::~KeepassEntryView(){
for(int i=0;i<ColumnSizes.size();i++){
	config.ColumnSizes[i]=(int)(ColumnSizes[i]*10000.0f);
}
}


void KeepassEntryView::contextMenuEvent(QContextMenuEvent* e){
if(itemAt(e->pos())){
	EntryViewItem* item=(EntryViewItem*)itemAt(e->pos());
	if(selectedItems().size()==0){
		setItemSelected(item,true);}
	else{
		bool AlreadySelected=false;
		for(int i=0;i<selectedItems().size();i++){
			if(selectedItems()[i]==item){AlreadySelected=true; break;}
		}
		if(!AlreadySelected){
			while(selectedItems().size()){
				setItemSelected(selectedItems()[0],false);
			}
			setItemSelected(item,true);
		}
	}
}
else
{while(selectedItems().size()){
	setItemSelected(selectedItems()[0],false);}
}

e->accept();
ContextMenu->popup(e->globalPos());
}

void KeepassEntryView::resizeEvent(QResizeEvent* e){
resizeColumns();
e->accept();
}

void KeepassEntryView::updateItems(){
updateItems(CurrentGroup);
}


void KeepassEntryView::updateItems(unsigned int GroupID){
QList<QTreeWidgetItem*> ItemSelec=selectedItems();
QList<quint32> SelectionIDs;
for(int i=0; i<ItemSelec.size(); i++)
	SelectionIDs << ((EntryViewItem*)ItemSelec[i])->pEntry->sID;
IsSearchGroup=false;
clear();
Items.clear();
if(!db)return;
if(!GroupID)return;
CurrentGroup=GroupID;
for(int i=0;i<db->numEntries();i++){
  if(db->entry(i).GroupID==GroupID)
  	setEntry(&db->entry(i));
}
if(SelectionIDs.size())
	for(int i=0;i<Items.size();i++){
		for(int j=0; j<SelectionIDs.size();j++){
			if(Items[i]->pEntry->sID==SelectionIDs[j]) setItemSelected(Items[i],true);}
	}
}

void KeepassEntryView::showSearchResults(QList<quint32>& results){
IsSearchGroup=true;
clear();
Items.clear();
for(int j=0; j<results.size(); j++){
	for(int i=0; i<db->numEntries();i++){
		if(db->entry(i).sID == results[j])
 		setEntry(&db->entry(i));
	}
}
}

void KeepassEntryView::setEntry(CEntry* entry){
  EntryViewItem* tmp=NULL;
  Items.push_back(tmp=new EntryViewItem(this));
  Items.back()->pEntry=entry;
  int j=0;
  if(config.Columns[0]){
    tmp->setText(j++,entry->Title);}
  if(config.Columns[1]){
    if(config.ListView_HideUsernames)
      tmp->setText(j++,"******");
    else
      tmp->setText(j++,entry->UserName);}
  if(config.Columns[2]){
    tmp->setText(j++,entry->URL);}
  if(config.Columns[3]){
    if(config.ListView_HidePasswords)
      tmp->setText(j++,"******");
    else{
	  entry->Password.unlock();
      tmp->setText(j++,entry->Password.string());
      entry->Password.lock();}}
  if(config.Columns[4]){
    tmp->setText(j++,entry->Additional.section('\n',0,0));}
  if(config.Columns[5]){
    tmp->setText(j++,entry->Expire.dateToString(Qt::LocalDate));}
  if(config.Columns[6]){
    tmp->setText(j++,entry->Creation.dateToString(Qt::LocalDate));}
  if(config.Columns[7]){
    tmp->setText(j++,entry->LastMod.dateToString(Qt::LocalDate));}
  if(config.Columns[8]){
    tmp->setText(j++,entry->LastAccess.dateToString(Qt::LocalDate));}
  if(config.Columns[9]){
   tmp->setText(j++,entry->BinaryDesc);}
  Items.back()->setIcon(0,db->icon(entry->ImageID));
}

void KeepassEntryView::refreshItems(){
EntryViewItem *tmp=NULL;
for(int i=0;i<Items.size();i++){
  tmp=Items[i];
  CEntry* entry=tmp->pEntry;

  int j=0;
  if(config.Columns[0]){
    tmp->setText(j++,entry->Title);}
  if(config.Columns[1]){
    if(config.ListView_HideUsernames)
      tmp->setText(j++,"******");
    else
      tmp->setText(j++,entry->UserName);}
  if(config.Columns[2]){
    tmp->setText(j++,entry->URL);}
  if(config.Columns[3]){
    if(config.ListView_HidePasswords)
      tmp->setText(j++,"******");
    else{
      entry->Password.unlock();
      tmp->setText(j++,entry->Password.string());
      entry->Password.lock();}}
  if(config.Columns[4]){
    tmp->setText(j++,entry->Additional.section('\n',0,0));}
  if(config.Columns[5]){
    tmp->setText(j++,entry->Expire.dateToString(Qt::LocalDate));}
  if(config.Columns[6]){
    tmp->setText(j++,entry->Creation.dateToString(Qt::LocalDate));}
  if(config.Columns[7]){
    tmp->setText(j++,entry->LastMod.dateToString(Qt::LocalDate));}
  if(config.Columns[8]){
    tmp->setText(j++,entry->LastAccess.dateToString(Qt::LocalDate));}
  if(config.Columns[9]){
   tmp->setText(j++,entry->BinaryDesc);}
  tmp->setIcon(0,db->icon(entry->ImageID));
}
}


void KeepassEntryView::updateColumns(){
setColumnCount(0);
QStringList cols;
if(config.Columns[0]){
 cols << tr("Title");}
if(config.Columns[1]){
 cols << tr("Username");}
if(config.Columns[2]){
 cols << tr("URL");}
if(config.Columns[3]){
 cols << tr("Password");}
if(config.Columns[4]){
 cols << tr("Comments");}
if(config.Columns[5]){
 cols << tr("Expires");}
if(config.Columns[6]){
 cols << tr("Creation");}
if(config.Columns[7]){
 cols << tr("Last Change");}
if(config.Columns[8]){
 cols << tr("Last Access");}
if(config.Columns[9]){
 cols << tr("Attachment");}
setHeaderLabels(cols);
resizeColumns();
}

void KeepassEntryView::resizeColumns(){
AutoResizeColumns=false;
if(!header()->count())return;

for(int i=0;i<NUM_COLUMNS;i++)
	if(!config.Columns[i])ColumnSizes[i]=0;

for(int i=0;i<NUM_COLUMNS;i++)
	if(config.Columns[i] && ColumnSizes[i]==0)ColumnSizes[i]=0.1f;

float sum=0;
for(int i=0;i<NUM_COLUMNS;i++)
	sum+=ColumnSizes[i];

for(int i=0;i<NUM_COLUMNS;i++)
	ColumnSizes[i]/=sum;

int w=viewport()->width();
int wx=0; int j=0;


for(int i=0;i<NUM_COLUMNS;i++){
	if(!config.Columns[i])continue;
	int NewWidth=(int)(ColumnSizes[i]*(float)w);
	wx+=NewWidth;
	header()->resizeSection(j++,NewWidth);
	//add rounding difference (w-wx) to the last column
	if(j==header()->count()){
		header()->resizeSection(j-1,header()->sectionSize(j-1)+(w-wx));
	}
}

AutoResizeColumns=true;

}


void KeepassEntryView::OnColumnResized(int index,int Old, int New){
if(!AutoResizeColumns)return;

int i=0; int c=-1;
for(i;i<ColumnSizes.size();i++){
	if(config.Columns[i])c++;
	if(c==index)break;
}

int j=0; c=-1; bool IsLastColumn=true;
for(j;j<ColumnSizes.size();j++){
	if(config.Columns[j])c++;
	if(c==(index+1)){IsLastColumn=false; break;}
}

if(IsLastColumn){
	j=0; c=-1;
	for(j;j<ColumnSizes.size();j++){
		if(config.Columns[j])c++;
		if(c==(index-1))break;
	}
}

int w=viewport()->width();
float div=(float)(New-Old)/(float)w;

if(((ColumnSizes[j]-div)*w > 2)){
	ColumnSizes[j]-=div;
	ColumnSizes[i]+=div;
}
resizeColumns();
}

void KeepassEntryView::mousePressEvent(QMouseEvent *event){
//save event position - maybe this is the start of a drag
if (event->button() == Qt::LeftButton)
            DragStartPos = event->pos();
//call base function
QTreeWidget::mousePressEvent(event);
}

void KeepassEntryView::mouseMoveEvent(QMouseEvent *event){
if(IsSearchGroup)
	return;
if (!(event->buttons() & Qt::LeftButton))
	return;
if ((event->pos() - DragStartPos).manhattanLength() < QApplication::startDragDistance())
	return;

DragItems.clear();
EntryViewItem* DragStartItem=(EntryViewItem*)itemAt(DragStartPos);
if(!DragStartItem){
	while(selectedItems().size()){
		setItemSelected(selectedItems()[0],false);}
	return;
}
if(selectedItems().size()==0){
		setItemSelected(DragStartItem,true);}
else{
	bool AlreadySelected=false;
	for(int i=0;i<selectedItems().size();i++){
		if(selectedItems()[i]==DragStartItem){AlreadySelected=true; break;}
	}
	if(!AlreadySelected){
		while(selectedItems().size()){
			setItemSelected(selectedItems()[0],false);
		}
		setItemSelected(DragStartItem,true);
	}
}

DragItems=selectedItems();
QDrag *drag = new QDrag(this);
QFontMetrics fontmet(DragStartItem->font(0));
int DragPixmHeight=16;
if(fontmet.height()>16)DragPixmHeight=fontmet.height();
QString DragText;
if(DragItems.size()>1)DragText=QString(tr("%1 items")).arg(DragItems.size());
else DragText=((EntryViewItem*)DragItems[0])->pEntry->Title;
DragPixmap  = QPixmap(fontmet.width(DragText)+19,DragPixmHeight);
DragPixmap.fill(QColor(255,255,255));
QPainter painter(&DragPixmap);
painter.setPen(QColor(0,0,0));
painter.setFont(DragItems[0]->font(0));
painter.drawPixmap(0,0,DragItems[0]->icon(0).pixmap(QSize(16,16)));
painter.drawText(19,DragPixmHeight-fontmet.strikeOutPos(),DragText);	
QMimeData *mimeData = new QMimeData;
void* pDragItems=&DragItems;
mimeData->setData("keepass/entry",QByteArray((char*)&pDragItems,sizeof(void*)));
drag->setMimeData(mimeData);
drag->setPixmap(DragPixmap);
drag->start();
}


void KeepassEntryView::paintEvent(QPaintEvent * event){
QTreeWidget::paintEvent(event);
}


EntryViewItem::EntryViewItem(QTreeWidget *parent):QTreeWidgetItem(parent){

}

EntryViewItem::EntryViewItem(QTreeWidget *parent, QTreeWidgetItem *preceding):QTreeWidgetItem(parent,preceding){

}

EntryViewItem::EntryViewItem(QTreeWidgetItem *parent):QTreeWidgetItem(parent){

}

EntryViewItem::EntryViewItem(QTreeWidgetItem *parent, QTreeWidgetItem *preceding):QTreeWidgetItem(parent,preceding){

}


bool EntryViewItem::operator<(const QTreeWidgetItem& other)const{
int SortCol=treeWidget()->sortColumn();
if(SortCol < 5 || SortCol==9){ //columns with string values (Title, Username, Password, URL, Comment)
	if(QString::localeAwareCompare(text(SortCol),other.text(SortCol)) < 0)
		return true;
	else 
		return false;
}
QDateTime *DateThis;
QDateTime *DateOther;

switch(SortCol){
	case 5: DateThis=&pEntry->Expire;
			DateOther=&((EntryViewItem&)other).pEntry->Expire;
			break;
	case 6: DateThis=&pEntry->Creation;
			DateOther=&((EntryViewItem&)other).pEntry->Creation;
			break;
	case 7: DateThis=&pEntry->LastMod;
			DateOther=&((EntryViewItem&)other).pEntry->LastMod;
			break;
	case 8: DateThis=&pEntry->LastAccess;
			DateOther=&((EntryViewItem&)other).pEntry->LastAccess;
			break;
	default:Q_ASSERT(false);
}
return *DateThis < *DateOther;
}
