###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sysaid_unauth_file_upload_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# SysAid Unauthenticated File Upload Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = 'cpe:/a:sysaid:sysaid';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106006");
  script_version("$Revision: 11872 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-06-11 10:02:43 +0700 (Thu, 11 Jun 2015)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-2995");

  script_name("SysAid Unauthenticated File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sysaid_detect.nasl");
  script_mandatory_keys("sysaid/installed");

  script_tag(name:"summary", value:"SysAid Help Desktop Software is prone to a unauthenticated
file upload vulnerability");

  script_tag(name:"vuldetect", value:"Determine if the vulnerable service is reachable and then
check the version.");

  script_tag(name:"insight", value:"The vulnerability exists in the RdsLogsEntry servlet which
accepts unauthenticated file uploads and handles zip file contents in a insecure way. Note that this
will only work if the target is running Java 6 or 7 up to 7u25, as Java 7u40 and above introduce a protection
against null byte injection in file names.");

  script_tag(name:"impact", value:"An unauthenticated attacker can upload arbitrary files which could
lead to remote code execution.");

  script_tag(name:"affected", value:"SysAid Help Desktop version 15.1.x and before.");

  script_tag(name:"solution", value:"Upgrade to version 15.2 or later.");

  script_xref(name:"URL", value:"https://www.security-database.com/detail.php?alert=CVE-2015-2995");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) ) exit( 0 );
vers = infos['version'];
dir = infos['location'];

if( ! dir ) exit(0);

if (dir == "/")
  dir = "";

url = dir + '/rdslogs?rdsName=' + rand_str(length:4);
req = string('POST ', url, ' HTTP/1.1\r\n',
             'Host: ', get_host_name(), '\r\n\r\n');
buf = http_keepalive_send_recv(port: port, data: req);
if (buf =~ "HTTP/1\.. 200" && version_is_less(version: vers, test_version: "15.2")) {
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     15.2\n';

  security_message(port: port, data: report);
  exit(0);
}

exit(99);
