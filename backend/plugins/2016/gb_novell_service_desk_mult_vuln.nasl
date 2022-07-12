###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_service_desk_mult_vuln.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Novell Service Desk Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = 'cpe:/a:novell:service_desk';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807538");
  script_version("$Revision: 12149 $");
  script_cve_id("CVE-2016-1593", "CVE-2016-1594", "CVE-2016-1595", "CVE-2016-1596");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-06 16:24:55 +0530 (Wed, 06 Apr 2016)");
  script_name("Novell Service Desk Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with
  Novell Service Desk and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to,

  - An insufficient validation of user supplied input in the 'import users'
    and 'file download' functionalities.

  - A vulnerability in the access control enforcement of the file download
    functionality.

  - Insufficient validation of user supplied input via fields
   'tf_aClientFirstName', 'tf_aClientLastName' in customer portal,
   'ta_selectedTopicContent' in Forums, 'tf_orgUnitName' in
    User -> Organizational Units and 'manufacturer name', 'address' and 'city' in
    Configuration -> Vendors, other fields also might be vulnerable.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated attackers to upload arbitrary files to the server and this could
  lead to remote code execution, to read arbitrary file attachments, to inject
  arbitrary javascript into the context of other users' browser sessions
  (including administrative users) and to obtain sensitive information.");

  script_tag(name:"affected", value:"Novell Service Desk versions 7.0.3 and 7.1");

  script_tag(name:"solution", value:"Update to Novell Service Desk version 7.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/136646");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/538043");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7017428");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7017429");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7017431");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7017430");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_novell_service_desk_remote_detect.nasl");
  script_mandatory_keys("Novell/Service/Desk/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!novellPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!novellVer = get_app_version(cpe:CPE, port:novellPort)){
  exit(0);
}

if(version_is_equal(version:novellVer, test_version:"7.0.3") ||
   version_is_equal(version:novellVer, test_version:"7.1"))
{
  report = report_fixed_ver(installed_version:novellVer, fixed_version:"7.2");
  security_message(data:report, port:novellPort);
  exit(0);
}
