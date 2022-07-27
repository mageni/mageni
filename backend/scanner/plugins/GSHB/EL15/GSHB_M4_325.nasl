##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_325.nasl 10623 2018-07-25 15:14:01Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.325
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
  script_oid("1.3.6.1.4.1.25623.1.0.94234");
  script_version("$Revision: 10623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("IT-Grundschutz M4.325: Lˆschen von Auslagerungsdateien");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04325.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_PolSecSet.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SSH_cryptsetup_swap.nasl");
  script_tag(name:"summary", value:"IT-Grundschutz M4.325: Lˆschen von Auslagerungsdateien

Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.325: Lˆschen von Auslagerungsdateien\n';

OSNAME = get_kb_item("WMI/WMI_OSNAME");
PAGEFILE = get_kb_item("WMI/cps/ClearPageFileAtShutdown");
CPSGENERAL = get_kb_item("WMI/cps/GENERAL");
wmilog = get_kb_item("WMI/cps/GENERAL/log");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");

cryptsetupinst = get_kb_item("GSHB/cryptsetup/inst");
cryptsetupfstab = get_kb_item("GSHB/cryptsetup/fstab");
sshlog = get_kb_item("GSHB/cryptsetup/log");

if(OSNAME >!< "none"){
  if(CPSGENERAL == "error"){
    result = string("Fehler");
    if (!wmilog) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (wmilog) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + wmilog);
  }else if(!CPSGENERAL){
   result = string("Fehler");
   desc = string("Beim Testen des Systems trat ein Fehler auf.\nEs konnte keine RSOP Abfrage durchgef¸hrt werden.");
  }else if (PAGEFILE == "1"){
    result = string("erf¸llt");
    desc = string('Das lˆschen der Auslagerungsdatei des virtuellen\nArbeitspeichers ist aktiviert.');
  }else{
    result = string("nicht erf¸llt");
    desc = string('Das lˆschen der Auslagerungsdatei des virtuellen\nArbeitspeichers ist nicht aktiviert.');
  }

}else{
  if(cryptsetupinst == "windows") {
    result = string("Fehler");
    if (OSNAME >!< "none" && OSNAME >!< "error") desc = string('Folgendes System wurde erkannt:\n' + OSNAME + '\nAllerdings konnte auf das System nicht korrekt\nzugegriffen werden. Folgende Fehler sind aufgetreten:\n' + WMIOSLOG);
    else desc = string('Das System scheint ein Windows-System zu sein.\nAllerdings konnte auf das System nicht korrekt\nzugegriffen werden. Folgende Fehler sind aufgetreten:\n' + WMIOSLOG);
  }else if(cryptsetupinst == "error"){
    result = string("Fehler");
    if (!sshlog) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (sshlog) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + sshlog);
  }else if(cryptsetupinst == "no"){
    result = string("nicht erf¸llt");
    desc = string('Das Paket cryptsetup ist nicht installiert.\nDavon ausgehend ist die SWAP Partition nicht\nverschl¸sselt.');
  }else if(cryptsetupinst == "yes" && cryptsetupfstab == "no"){
    result = string("nicht erf¸llt");
    desc = string('Das Paket cryptsetup ist installiert. Allerdings wurde\nkein Entsprechender Eintrag f¸r eine verschl¸sselte\nSWAP Partition in /etc/fstab gefunden.');
  }else if(cryptsetupinst == "yes" && cryptsetupfstab != "no"){
    result = string("erf¸llt");
    desc = string('Das Paket cryptsetup ist installiert. Es wurde\nfolgender Eintrag f¸r eine verschl¸sselte SWAP\nPartition in /etc/fstab gefunden:\n' + cryptsetupfstab);
  }
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.');
}

set_kb_item(name:"GSHB/M4_325/result", value:result);
set_kb_item(name:"GSHB/M4_325/desc", value:desc);
set_kb_item(name:"GSHB/M4_325/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_325');

exit(0);
