###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_305.nasl 10646 2018-07-27 07:00:22Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.305
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
  script_oid("1.3.6.1.4.1.25623.1.0.94230");
  script_version("$Revision: 10646 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("IT-Grundschutz M4.305: Einsatz von Speicherbeschr‰nkungen (Quotas)");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04305.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15");
  script_dependencies("GSHB/GSHB_SSH_quota.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"IT-Grundschutz M4.305: Einsatz von Speicherbeschr‰nkungen (Quotas).

  Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.305: Einsatz von Speicherbeschr‰nkungen (Quotas)\n';

gshbm =  "IT-Grundschutz M4.305: ";

uname = get_kb_item("GSHB/quota/uname");
fstab = get_kb_item("GSHB/quota/fstab");
user = get_kb_item("GSHB/quota/user");
group = get_kb_item("GSHB/quota/group");
log = get_kb_item("GSHB/quota/log");
zfsquota = get_kb_item("GSHB/quota/zfsquota");
ufsquota = get_kb_item("GSHB/quota/ufsquota");

OSNAME = get_kb_item("WMI/WMI_OSNAME");

if(OSNAME >!< "none"){
  result = string("nicht zutreffend");
  desc = string('Folgendes System wurde erkannt:\n' + OSNAME);
}else if(fstab == "windows") {
    result = string("nicht zutreffend");
    desc = string('Das System scheint ein Windows-System zu sein.');
}else if(uname =~ "SunOS.*"){
    if(ufsquota >< "norepquota" && zfsquota >< "nozfs"){
    result = string("Fehler");
    desc = string('Auf dem System konnte weder der Befehl "repquota -va" noch der\nBefehl "zfs get quota", zum ermitteln der Quotaeinstellungen,\nausgef¸hrt werden.');
  }else if(ufsquota >< "noquota" && zfsquota >< "noquota"){
    result = string("nicht erf¸llt");
    desc = string('Auf dem System konnten keine Quotaeinstellungen\ngefunden werden.');
  }else if ((ufsquota >!< "noquota" && ufsquota >!< "norepquota") || (zfsquota >!< "noquota" && zfsquota >!< "nozfs")){
    result = string("erf¸llt");
    desc = string('Auf dem System konnten folgende Volumes mit\nQuotaeinstellungen gefunden werden:');
    if (ufsquota >!< "noquota" && ufsquota >!< "norepquota")desc += string('\n' + ufsquota);
    if (zfsquota >!< "noquota" && zfsquota >!< "nozfs")desc += string('\n' + zfsquota);
  }else{
  result = string("Fehler");
  if (!log)desc = string('Beim Testen des Systems trat ein unbekannter\nFehler auf.');
  if (log)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + log);
  }
}else if(fstab >< "error"){
  result = string("Fehler");
  if (!log)desc = string('Beim Testen des Systems trat ein unbekannter\nFehler auf.');
  if (log)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + log);
}else if(fstab >< "none"){
  result = string("nicht erf¸llt");
  desc = string('Auf dem System konnten keine Quotaeinstellungen\ngefunden werden.');
}else if(((user >!< "none" && user >!< "nols") || (group >!< "none" && group >!< "nols")) && (fstab >!< "none" && fstab != "nogrep")){
  result = string("erf¸llt");
  desc = string('Auf dem System konnten folgende Volumes mit Quota-\neinstellungen gefunden werden:\n' + fstab);
}else if (user >< "nols" || group >< "nols" || fstab >< "nogrep"){
  result = string("Fehler");
  if (user >< "nols" || group >< "nols")  desc = string('Beim Testen des Systems wurde der Befehl ls\nnicht gefunden.\n');
  if (fstab >< "nogrep")  desc += string('Beim Testen des Systems wurde der Befehl grep\nnicht gefunden.');
}

set_kb_item(name:"GSHB/M4_305/result", value:result);
set_kb_item(name:"GSHB/M4_305/desc", value:desc);
set_kb_item(name:"GSHB/M4_305/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_305');

exit(0);
