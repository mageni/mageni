##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_policy_orientierungshilfe_win10_ok.nasl 10530 2018-07-17 14:15:42Z asteins $
#
# AKIF Orientierungshilfe Windows 10: Erfuellt
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108079");
  script_version("$Revision: 10530 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-17 16:15:42 +0200 (Tue, 17 Jul 2018) $");
  script_tag(name:"creation_date", value:"2017-02-10 10:55:08 +0100 (Fri, 10 Feb 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("AKIF Orientierungshilfe Windows 10: Erfuellt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("Policy/gb_policy_orientierungshilfe_win10.nasl");
  script_mandatory_keys("policy/orientierungshilfe_win10/passed");

  script_tag(name:"summary", value:"Listet alle erfuellten Tests der 'AKIF Orientierungshilfe Windows 10 Ueberpruefung' auf.");

  script_tag(name:"qod", value:"98");

  exit(0);
}

passed = get_kb_item( "policy/orientierungshilfe_win10/passed" );

if( passed ) {

  passed = split( passed, sep:"#-#", keep:FALSE );

  report = max_index( passed ) + ' Bestanden:\n\n';

  foreach line( passed ) {
    entry = split( line, sep:"||", keep:FALSE );
    report += "Beschreibung:             " + entry[0] + '\n';
    report += "Nummerierung:             " + entry[1] + '\n';
    report += "Ueberpruefung:            " + entry[2] + '\n';
    if( entry[2] == "Registry" ) {
      report += "Registry-Key:             " + entry[3] + '\n';
      report += "Registry-Name:            " + entry[4] + '\n';
      report += "Registry-Typ:             " + entry[5] + '\n';
      report += "Erwarteter Registry-Wert: " + entry[6] + '\n';
      report += "Momentaner Registry-Wert: " + entry[7] + '\n';
    } else if( entry[2] == "Service" ) {
      report += "Service-Name:             " + entry[3] + '\n';
      report += "Erwarteter Startup-Type:  " + entry[4] + '\n';
      report += "Momentaner Startup-Type:  " + entry[5] + '\n';
    }
    report += '\n';
  }
  log_message( data:report, port:0 );
}

exit( 0 );
