###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_infoblox_netmri_shell_escape_priv_esc.nasl 12998 2019-01-09 13:46:07Z asteins $
#
# Infoblox NetMRI Administration Shell Escape and Privilege Escalation Vulnerability
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.107340");
  script_version("2019-03-22T15:58:59+0000");
  script_tag(name:"last_modification", value:"2019-03-22 15:58:59 +0000 (Fri, 22 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-09-10 15:43:15 +0200 (Mon, 10 Sep 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Infoblox NetMRI Administration Shell Escape and Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_netmri_detect.nasl");
  script_mandatory_keys("netMRI/detected");
  script_tag(name:"summary", value:"The administrative shell of Infoblox NetMRI 7.1.2 through 7.1.4 is prone to a
shell escape and privilege escalation vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated user can escape the management shell and subsequently
escalate to root via insecure file ownership and sudo permissions.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to gain complete control over
the target system.");

  script_tag(name:"affected", value:"Infoblox NetMRI version 7.1.2 through 7.1.4. Other versions might be affected
as well.");

  script_tag(name:"solution", value:"No known solution is available as of 22nd March, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.korelogic.com/Resources/Advisories/KL-001-2017-017.txt");

  exit(0);
}

CPE = "cpe:/a:infoblox:netmri";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if (version_in_range(version: version, test_version: "7.1.2", test_version2: "7.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message( data: report, port: port);
  exit(0);
}
exit( 99 );
