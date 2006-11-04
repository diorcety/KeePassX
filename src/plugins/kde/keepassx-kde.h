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

#include <QtPlugin>
#include <QObject>
#include "../interfaces/IFileDialog.h"
#include "../interfaces/IKdeInit.h"


class KdePlugin:public QObject,public IFileDialog,public IKdeInit{
	Q_OBJECT
	Q_INTERFACES(IFileDialog)
	Q_INTERFACES(IKdeInit)
	public:
		virtual QString openExistingFileDialog(QWidget* parent,QString title,QString dir,
							QStringList Filters);
		virtual QStringList openExistingFilesDialog(QWidget* parent,QString title,QString dir,
							QStringList Filters);		
		virtual QString saveFileDialog(QWidget* parent,QString title,QString dir,
							QStringList Filters,bool ShowOverwriteWarning=true);
		virtual QApplication* getMainAppObject(int argc, char** argv);
	
};
