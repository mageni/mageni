###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_mult_xss_vuln01_apr14.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# ownCloud Multiple XSS Vulnerabilities-01 Apr14
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804361");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2013-0201", "CVE-2013-0202", "CVE-2013-0203");
  script_bugtraq_id(57497);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-04 14:54:56 +0530 (Fri, 04 Apr 2014)");
  script_name("ownCloud Multiple XSS Vulnerabilities-01 Apr14");

  script_tag(name:"summary", value:"This host is installed with ownCloud and is prone to multiple XSS
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Unspecified input passed to core/lostpassword/templates/resetpassword.php is
  not properly sanitized before being used.

  - Input passed via the 'mime' parameter to apps/files/ajax/mimeicon.php is not
  properly sanitized before being used.

  - Input passed via the 'token' parameter to apps/gallery/sharing.php is not
  properly sanitized before being used.

  - Input passed via the 'action' parameter to core/ajax/sharing.php is not
  properly sanitized before being used.

  - Unspecified input passed to apps/calendar/ajax/event/new.php is not
  properly sanitized before being used.

  - Input passed via the 'url' parameter to apps/bookmarks/ajax/addBookmark.php
  is not properly sanitized before being used.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary script
code in a user's browser within the trust relationship between their browser
and the server.");
  script_tag(name:"affected", value:"ownCloud Server version 4.5.x before 4.5.6 and 4.0.x before 4.0.11");
  script_tag(name:"solution", value:"Upgrade to ownCloud version 4.5.6 or 4.0.11 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51872");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/01/22/12");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oc-sa-2013-001");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl");
  script_mandatory_keys("owncloud/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ownPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ownVer = get_app_version(cpe:CPE, port:ownPort)){
  exit(0);
}

if(version_in_range(version:ownVer, test_version:"4.5.0", test_version2:"4.5.5")||
   version_in_range(version:ownVer, test_version:"4.0.0", test_version2:"4.0.10"))
{
  security_message(port:ownPort);
  exit(0);
}
