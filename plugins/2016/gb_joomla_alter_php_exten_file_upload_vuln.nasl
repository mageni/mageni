###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_alter_php_exten_file_upload_vuln.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Joomla Alternative PHP File Extensions File Upload and Information Disclosure Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809744");
  script_version("$Revision: 12149 $");
  script_cve_id("CVE-2016-9836", "CVE-2016-9837");
  script_bugtraq_id(94663, 94892);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-07 16:06:46 +0530 (Wed, 07 Dec 2016)");

  script_name("Joomla Alternative PHP File Extensions File Upload and Information Disclosure Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Joomla and is prone
  to file upload and information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to,

  - An error in file scanning mechanism of 'JFilterInput::isFileSafe' function
    which does not consider alternative PHP file extensions when checking
    uploaded files for PHP content.

  - Inadequate ACL checks in the Beez3 com_content article layout override.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to gain access to potentially sensitive information and
  upload and execute files with the '.php6', '.php7', '.phtml', and '.phpt'
  extensions.");

  script_tag(name:"affected", value:"Joomla core versions 3.0.0 through 3.6.4");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.6.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://github.com/XiphosResearch/exploits/tree/master/Joomraa");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/665-20161202-core-shell-upload.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/666-20161203-core-information-disclosure.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www.joomla.org");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!jPort = get_app_port(cpe:CPE))
  exit(0);

if(!jVer = get_app_version(cpe:CPE, port:jPort))
  exit(0);

if( jVer =~ "^3" ) {
  if(version_in_range(version:jVer, test_version:"3.0.0", test_version2:"3.6.4")) {
    report = report_fixed_ver( installed_version:jVer, fixed_version:"3.6.5" );
    security_message( data:report, port:jPort);
    exit(0);
  }
}

exit(0);
