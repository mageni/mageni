###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_mult_vuln01_july14.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# ownCloud Multiple Vulnerabilities-01 July14
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
  script_oid("1.3.6.1.4.1.25623.1.0.804658");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2012-5056", "CVE-2012-5057", "CVE-2012-5336");
  script_bugtraq_id(68295, 68305);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-07-03 12:50:12 +0530 (Thu, 03 Jul 2014)");
  script_name("ownCloud Multiple Vulnerabilities-01 July14");


  script_tag(name:"summary", value:"This host is installed with ownCloud and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to an,

  - Input passed to 'apps/files_odfviewer/src/webodf/webodf/flashput/PUT.swf'
  script via 'readyCallback' parameter is not sanitized before returning it to
  users.

  - Input passed to 'lib/db.php' script via malformed query is not sanitized
  before returning it to users.

  - Input passed to 'apps/gallery/templates/index.php' script via 'root'
  parameter is not sanitized before returning it to users.

  - Application does not validate the URL path upon submission to the 'index.php'
  script.

  - Improper validation of input passed to 'lib/base.php' script via
  'user_id session' variable.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain access to
arbitrary user files, insert arbitrary HTTP headers and execute arbitrary
script code in a user's browser session within the trust relationship
between their browser and the server.");
  script_tag(name:"affected", value:"ownCloud Server 4.0.x before 4.0.8");
  script_tag(name:"solution", value:"Upgrade to ownCloud version 4.0.8 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/CVE-2012-5336");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/CVE-2012-5057");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/CVE-2012-5056");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl");
  script_mandatory_keys("owncloud/installed");
  script_require_ports("Services/www", 80);
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

if(version_in_range(version:ownVer, test_version:"4.0.0", test_version2:"4.0.7"))
{
  security_message(port:ownPort);
  exit(0);
}
