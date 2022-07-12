###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_mult_xss_n_csrf_vuln02_may14.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# ownCloud Multiple XSS & CSRF Vulnerabilities -02 May14
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
  script_oid("1.3.6.1.4.1.25623.1.0.804277");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2013-0300", "CVE-2013-0298");
  script_bugtraq_id(58107, 58103);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-05-05 11:00:11 +0530 (Mon, 05 May 2014)");
  script_name("ownCloud Multiple XSS & CSRF Vulnerabilities -02 May14");


  script_tag(name:"summary", value:"This host is installed with ownCloud and is prone to multiple cross-site
scripting and cross-site request forgery vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Improper validation of user-supplied input passed via 'mountpoint' parameter
upon submission to the /apps/files_external/addMountPoint.php script, 'dir' and
'file' parameters upon submission to the /apps/files_pdfviewer/viewer.php script
and 'iCalendar' file in the calendar application.

  - Insufficient validation of user-supplied input passed via the the 'v' POST
parameter to changeview.php within /apps/calendar/ajax, multiple unspecified
parameters to addRootCertificate.php, dropbox.php and google.php scripts within
/apps/files_external/ajax and multiple unspecified POST parameters to
settings.php script within /apps/user_webdavauth.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct request forgery
attacks and execute arbitrary script code in a user's browser.");
  script_tag(name:"affected", value:"ownCloud Server before version 4.5.x before 4.5.7");
  script_tag(name:"solution", value:"Upgrade to ownCloud version 4.5.7 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q1/378");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-004");
  script_xref(name:"URL", value:"http://owncloud.org/about/security/advisories/oC-SA-2013-003");
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

if(version_in_range(version:ownVer, test_version:"4.5.0", test_version2:"4.5.6"))
{
  security_message(port:ownPort);
  exit(0);
}
