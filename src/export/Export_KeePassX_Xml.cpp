/***************************************************************************
 *   Copyright (C) 2007 by Tarek Saidi                                     *
 *   tarek.saidi@arcor.de                                                  *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; version 2 of the License.               *

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

#include "Export_KeePassX_Xml.h"

bool Export_KeePassX_Xml::exportDatabase(QWidget* GuiParent,IDatabase* database,const QByteArray &key,CryptedFields fields){
	db=database;	
	QFile *file=openFile(GuiParent,identifier(),QStringList()<<tr("XML Files (*.xml)") << tr("All Files (*)"));
	if(!file)return false;
	QDomDocument doc("KEEPASSX_DATABASE");
	QDomElement root=doc.createElement("database");
    if(fields != NONE)
        root.setAttribute("crypted", true);
	doc.appendChild(root);
	QList<IGroupHandle*> Groups=db->sortedGroups();
	for(int i=0;i<Groups.size();i++){
		if(Groups[i]->parent()==NULL){
            addGroup(Groups[i],root,doc,key,fields);
		}
	}
	file->write(doc.toByteArray());
	file->close();
	delete file;
	return true;
}

void Export_KeePassX_Xml::addGroup(IGroupHandle* group,QDomElement& parent,QDomDocument& doc,const QByteArray &key,CryptedFields fields){
	QDomElement GroupElement=doc.createElement("group");
	parent.appendChild(GroupElement);
	QDomElement Title=doc.createElement("title");
	QDomElement Icon=doc.createElement("icon");
	Title.appendChild(doc.createTextNode(group->title()));
	Icon.appendChild(doc.createTextNode(QString::number(group->image())));
	GroupElement.appendChild(Title);
	GroupElement.appendChild(Icon);
	QList<IGroupHandle*> children=group->children();
	for(int i=0;i<children.size();i++){
        addGroup(children[i],GroupElement,doc,key,fields);
	}
	QList<IEntryHandle*> entries=db->entriesSortedStd(group);
	for(int i=0;i<entries.size();i++){
        addEntry(entries[i],GroupElement,doc,key,fields);
	}
	
}

void Export_KeePassX_Xml::addEntry(IEntryHandle* entry,QDomElement& parent,QDomDocument& doc,const QByteArray &key,CryptedFields fields){
	QDomElement GroupElement=doc.createElement("entry");
	parent.appendChild(GroupElement);
	QDomElement Title=doc.createElement("title");
	QDomElement Username=doc.createElement("username");
	QDomElement Password=doc.createElement("password");
	QDomElement Url=doc.createElement("url");
	QDomElement Comment=doc.createElement("comment");
	QDomElement BinaryDesc=doc.createElement("bindesc");
	QDomElement Binary=doc.createElement("bin");	
	QDomElement Icon=doc.createElement("icon");
	QDomElement Creation=doc.createElement("creation");
	QDomElement LastAccess=doc.createElement("lastaccess");	
	QDomElement LastMod=doc.createElement("lastmod");
	QDomElement Expire=doc.createElement("expire");	
	
	Title.appendChild(doc.createTextNode(entry->title()));
    cryptElement(doc, Username, entry->username(), key, fields & IExport::USERNAME);
	SecString password=entry->password();
	password.unlock();
    cryptElement(doc, Password, password.string(), key, fields & IExport::PASSWORD);
	password.lock();
    cryptElement(doc, Url, entry->url(), key, fields & IExport::URL);
    cryptElement(doc, Comment, entry->comment(), key, fields & IExport::COMMENT);
	bool HasAttachment=!entry->binary().isNull();
	if(HasAttachment){
        cryptElement(doc, BinaryDesc, entry->binaryDesc(), key, fields & IExport::BINARY);
        cryptElement(doc, Binary, entry->binary().toBase64(), key, fields & IExport::BINARY);
	}
	Icon.appendChild(doc.createTextNode(QString::number(entry->image())));
	Creation.appendChild(doc.createTextNode(entry->creation().toString(Qt::ISODate)));
	LastAccess.appendChild(doc.createTextNode(entry->lastAccess().toString(Qt::ISODate)));
	LastMod.appendChild(doc.createTextNode(entry->lastMod().toString(Qt::ISODate)));
	Expire.appendChild(doc.createTextNode(entry->expire().toString(Qt::ISODate)));
	GroupElement.appendChild(Title);
	GroupElement.appendChild(Username);
	GroupElement.appendChild(Password);
	GroupElement.appendChild(Url);
	GroupElement.appendChild(Comment);
	if(HasAttachment){
		GroupElement.appendChild(BinaryDesc);
		GroupElement.appendChild(Binary);
	}
	GroupElement.appendChild(Icon);
	GroupElement.appendChild(Creation);
	GroupElement.appendChild(LastAccess);
	GroupElement.appendChild(LastMod);
	GroupElement.appendChild(Expire);
}

void Export_KeePassX_Xml::cryptElement(QDomDocument &document, QDomElement &element,const QString &str, const QByteArray &key, bool crypt) {
    if(crypt) {
        QByteArray out;
        encrypt_data(str.toUtf8(), out, key);
        element.appendChild(document.createTextNode(out.toBase64()));
        element.setAttribute("crypted", true);
    } else{
        element.appendChild(document.createTextNode(str));
    }
}
