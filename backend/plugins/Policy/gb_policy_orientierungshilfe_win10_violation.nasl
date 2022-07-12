##############################################################################
# OpenVAS Vulnerability Test
#
# AKIF Orientierungshilfe Windows 10: Nicht erfuellt
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

# nb: Keep above the description part as it is used there
include("misc_func.inc");
include("version_func.inc");

# TODO: Remove once GVM-9 and GOS < 4.3.x is retired
# nb: includes in the description phase won't work anymore from GOS 4.2.11 (GVM TBD)
# onwards so checking for the defined_func and default to TRUE below if the funcs are undefined
if( defined_func( "get_local_gos_version" ) &&
    defined_func( "version_is_greater_equal" ) ) {
  gos_version = get_local_gos_version();
  if( strlen( gos_version ) > 0 &&
      version_is_greater_equal( version:gos_version, test_version:"4.2.4" ) ) {
    use_severity = TRUE;
  } else {
    use_severity = FALSE;
  }
} else {
  use_severity = TRUE;
}

if( OPENVAS_VERSION && version_is_greater_equal( version:OPENVAS_VERSION, test_version:"10" ) )
  use_severity = TRUE;

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108080");
  script_version("2019-05-07T10:42:32+0000");
  script_tag(name:"last_modification", value:"2019-05-07 10:42:32 +0000 (Tue, 07 May 2019)");
  script_tag(name:"creation_date", value:"2017-02-10 10:55:08 +0100 (Fri, 10 Feb 2017)");
  if( use_severity ) {
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  } else {
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  }
  script_name("AKIF Orientierungshilfe Windows 10: Nicht erfuellt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("Policy/gb_policy_orientierungshilfe_win10.nasl");
  script_mandatory_keys("policy/orientierungshilfe_win10/failed");

  script_tag(name:"summary", value:"Listet alle nicht erfuellten Tests der 'AKIF Orientierungshilfe Windows 10 Ueberpruefung' auf.");

  script_tag(name:"qod", value:"98");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

failed = get_kb_item( "policy/orientierungshilfe_win10/failed" );

if( failed ) {

  failed = split( failed, sep:"#-#", keep:FALSE );

  report = max_index( failed ) + ' Verstoesse:\n\n';

  foreach line( failed ) {
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
  if( use_severity )
    security_message( port:0, data:report );
  else
    log_message( port:0, data:report );
}

exit( 0 );
