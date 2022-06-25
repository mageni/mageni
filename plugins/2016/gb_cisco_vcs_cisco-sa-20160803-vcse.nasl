###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_vcs_cisco-sa-20160803-vcse.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Cisco TelePresence Video Communication Server Expressway Command Injection Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:cisco:telepresence_video_communication_server_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106168");
  script_cve_id("CVE-2016-1468");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_version("$Revision: 12338 $");

  script_name("Cisco TelePresence Video Communication Server Expressway Command Injection Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160803-vcse");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to the failure to properly sanitize user input
passed to the affected system's scripts. An attacker could exploit this vulnerability by submitting crafted
input to the affected fields of the web interface. Successful exploitation of this vulnerability could allow
an attacker to run arbitrary commands on the system.");

  script_tag(name:"solution", value:"Update to version X8.6 or later");

  script_tag(name:"summary", value:"A vulnerability in the administrative web interface of Cisco TelePresence
Video Communication Server Expressway could allow an authenticated, remote attacker to execute arbitrary
commands on the affected system.");

  script_tag(name:"affected", value:"Cisco TelePresence Video Communication Server Expressway version X8.5.2");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-08-04 13:00:53 +0700 (Thu, 04 Aug 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_vcs_detect.nasl", "gb_cisco_vcs_ssh_detect.nasl");
  script_mandatory_keys("cisco_vcs/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version =~ "^8\." )
{
  if( version_is_equal(version: version, test_version: "8.5.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.6" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

