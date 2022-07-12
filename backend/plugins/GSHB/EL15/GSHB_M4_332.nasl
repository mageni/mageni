##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_332.nasl 10396 2018-07-04 09:13:46Z cfischer $
#
# IT-Grundschutz, 14. EL, Maßnahme 4.332
#
# Authors:
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.94239");
  script_version("$Revision: 10396 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-04 11:13:46 +0200 (Wed, 04 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.332: Sichere Konfiguration der Zugriffssteuerung bei einem Samba-Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_dependencies("GSHB/GSHB_SSH_SAMBA_ntfs_ACL_ADS.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB-15");

  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04332.html");

  script_tag(name:"summary", value:"IT-Grundschutz M4.332: Sichere Konfiguration der Zugriffssteuerung bei einem Samba-Server

  Stand: 14. Ergänzungslieferung (14. EL).");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("itg.inc");
include("smb_nt.inc");

name = 'IT-Grundschutz M4.332: Sichere Konfiguration der Zugriffssteuerung bei einem Samba-Server\n';

samba = kb_smb_is_samba();
NTFSADS = get_kb_item("GSHB/SAMBA/NTFSADS");
ACL = get_kb_item("GSHB/SAMBA/ACL");
ACLSUPP = get_kb_item("GSHB/SAMBA/ACLSUPP");
VER = get_kb_item("GSHB/SAMBA/VER");
log = get_kb_item("GSHB/SAMBA/log");

if(!samba){
    result = string("nicht zutreffend");
    desc = string('Auf dem System läuft kein Samba-Dateiserver.');
}else if(NTFSADS == "error"){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(ACL != "no" && ACLSUPP != "no" && NTFSADS != "no"){
    result = string("erfüllt");
    desc = string('NTFS Access Control Lists und NTFS Alternate Data\nStreams wurde richtig konfiguriert. Bitte prüfen Sie\nob bei den aufgeführten Mountpoints noch welche\nfehlen. Wenn ja, aktivieren Sie auch dort den\nACL Support.\n' + ACL +'\n \n');
    desc += string('- Sind die Administratoren damit vertraut, wie Samba\ndas Windows-Rechtemodell im Unix-Dateisystem abbildet?\n- Wissen die Administratoren, wie die Unix-Rechte für\nneu erstellte Dateien zu Stande kommen?\n- Ist den Administratoren klar, wie sich das Entfernen\ndes DOS-Attibuts "Schreibschutz" auf die UNIX-Rechte\nauswirkt?\n- Wissen die Administratoren, dass die benutzer- und\ngruppenbezogenen Konfigurationsparameter die im Unix-\nDateisystem\ngültigen Zugriffsberechtigungen für\nBenutzer oder Gruppen überschreiben?');
}else if (ACL == "no" || ACLSUPP == "no" || NTFSADS == "no"){
    result = string("nicht erfüllt");
    if (ACLSUPP == "no")desc = string('Der Konfigurationsparameter -nt acl support- in der\nKonfigurationsdatei smb.conf steht nicht auf -yes-.\n \n');
    if (ACL == "no")desc += string('Es wurde in /etc/fstab keine Unterstützung für ACL\ngefunden. Sie müssen die ACL-Unterstützung explizit\naktivieren.\n \n');
    if (NTFSADS == "no")desc += string('Sie setzen Samba Version ' + VER + ' ein.\nSamba 3.0.x bietet keine Möglichkeit NTFS ADS\nabzubilden.\nSamba 3.2.x und höher kann NTFS ADS\ndirekt ber POSIX Extended Attributes (xattr) abbilden.');
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.');
}

set_kb_item(name:"GSHB/M4_332/result", value:result);
set_kb_item(name:"GSHB/M4_332/desc", value:desc);
set_kb_item(name:"GSHB/M4_332/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_332');

exit(0);
