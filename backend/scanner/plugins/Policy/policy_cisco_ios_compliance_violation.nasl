##############################################################################
# OpenVAS Vulnerability Test
#
# Cisco IOS Compliance Check: Failed
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106433");
  script_version("2019-05-07T10:42:32+0000");
  script_tag(name:"last_modification", value:"2019-05-07 10:42:32 +0000 (Tue, 07 May 2019)");
  script_tag(name:"creation_date", value:"2017-01-11 10:55:08 +0700 (Wed, 11 Jan 2017)");
  if( use_severity ) {
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  } else {
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  }

  script_tag(name:"qod", value:"98");
  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Cisco IOS Compliance Check: Failed");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("Policy/policy_cisco_ios_compliance.nasl");
  script_mandatory_keys("policy/cisco_ios_compliance/failed");

  script_tag(name:"summary", value:"Lists all the Cisco IOS Compliance Policy Checks which did NOT pass.");

  exit(0);
}

failed = get_kb_item("policy/cisco_ios_compliance/failed");

if (failed) {
  failed = split(failed, keep: FALSE);

  report = max_index(failed) + " Checks failed:\n\n";

  foreach line (failed) {
    entry = split(line, sep: "||", keep: FALSE);
    report += "Title:       " + entry[0] + "\n";
    report += "Description: " + entry[1] + "\n";
    report += "Solution:    " + entry[2] + "\n";
    if (max_index(entry) == 4)
      report += "Remediation: " + entry[3] + "\n";
    report += '\n';
  }

  if( use_severity )
    security_message( port:0, data:report );
  else
    log_message( port:0, data:report );
}

exit(0);
