###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_008.nasl 14124 2019-03-13 07:14:43Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 5.008
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
  script_oid("1.3.6.1.4.1.25623.1.0.95050");
  script_version("$Revision: 14124 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 08:14:43 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"general_note");
  script_name("IT-Grundschutz M5.008: Regelm‰ﬂiger Sicherheitscheck des Netzes");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05008.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_dependencies("compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");

  script_tag(name:"summary", value:"IT-Grundschutz M5.008: Regelm‰ﬂiger Sicherheitscheck des Netzes.

  Stand: 14. Erg‰nzungslieferung (14. EL).

  Hinweis:

  Es wird lediglich ein Meldung ausgegeben, dass mit aktuelleten Plugins getestet werden soll.");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M5.008: Regelm‰ﬂiger Sicherheitscheck des Netzes\n';

gshbm = "GSHB Maﬂnahme 5.008: ";

result = string("unvollst‰ndig");
desc = string("F¸hren Sie bitte eine Pr¸fung Ihres Netzwerkes mit dem aktuellen NVT-Set aus.");

set_kb_item(name:"GSHB/M5_008/result", value:result);
set_kb_item(name:"GSHB/M5_008/desc", value:desc);
set_kb_item(name:"GSHB/M5_008/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M5_008');

exit(0);