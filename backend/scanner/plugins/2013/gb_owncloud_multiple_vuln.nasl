###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_multiple_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# ownCloud Cross-Site Scripting and File Upload Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803741");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2012-5606", "CVE-2012-5607", "CVE-2012-5608", "CVE-2012-5609", "CVE-2012-5610");
  script_bugtraq_id(56658, 56764);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-08-21 16:55:36 +0530 (Wed, 21 Aug 2013)");
  script_name("ownCloud Cross-Site Scripting and File Upload Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("owncloud/installed");

  script_tag(name:"summary", value:"This host is running ownCloud and is prone to cross-site scripting and file
  upload vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP request and check whether it is able to read
  cookie or not.");

  script_tag(name:"solution", value:"Upgrade to ownCloud 4.5.2 or later.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An input passed via the filename to apps/files_versions/js/versions.js
  and apps/files/js/filelist.js and event title to
  3rdparty/fullcalendar/js/fullcalendar.js is not properly sanitised before
  being returned to the user.

  - Certain unspecified input passed to apps/user_webdavauth/settings.php is
  not properly sanitised before being returned to the user.

  - An error due to the lib/migrate.php and lib/filesystem.php scripts are not
  properly verifying uploaded files.");

  script_tag(name:"affected", value:"ownCloud versions before 4.0.9 and 4.5.0, 4.5.x before 4.5.2");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary HTML
  or script code or discloses sensitive information resulting in loss of confidentiality.");

  script_xref(name:"URL", value:"http://owncloud.org/changelog");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51357");
  script_xref(name:"URL", value:"https://github.com/owncloud/core/commit/ce66759");
  script_xref(name:"URL", value:"https://github.com/owncloud/core/commit/e45f36c");
  script_xref(name:"URL", value:"https://github.com/owncloud/core/commit/e5f2d46");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/11/30/3");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
url = dir + "/apps/files_versions/js/versions.js?filename='><script>alert(document.cookie)</script>";

if( http_vuln_check( port:port, url:url, pattern:"><script>alert\(document\.cookie\)</script>", check_header:TRUE, extra_check:"revertFile" ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
