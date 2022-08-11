###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manage_engine_servicedesk_plus_mult_unauth_info_disc_vuln.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# ManageEngine ServiceDesk Plus Multiple Unauthorized Information Disclosure Vulnerabilities
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

CPE = "cpe:/a:manageengine:servicedesk_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809071");
  script_version("$Revision: 12149 $");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-20 12:16:44 +0530 (Thu, 20 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("ManageEngine ServiceDesk Plus Multiple Unauthorized Information Disclosure Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with
  ManageEngine ServiceDesk Plus and is prone to multiple unauthorized information
  disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Multiple flaws are due to
  an inadequate access control over non-permissible functionalities
  under Request module.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker with low privilege to access non-permissible functionalities.");

  script_tag(name:"affected", value:"ManageEngine ServiceDesk Plus version
  9.2 Build 9207 (Other versions could also be affected).");

  script_tag(name:"solution", value:"Upgrade to ManageEngine ServiceDesk Plus
  9.2 Build 9228 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40569");
  script_xref(name:"URL", value:"https://www.manageengine.com/products/service-desk/readme-9.2.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ManageEngine_ServiceDesk_Plus_detect.nasl");
  script_mandatory_keys("ManageEngine/ServiceDeskPlus/installed");
  script_require_ports("Services/www", 8080);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!deskPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!deskVer = get_app_version(cpe:CPE, port:deskPort)){
  exit(0);
}

vers = str_replace(string:deskVer, find:"build", replace:".");

if(version_is_equal(version:vers, test_version:"9.2.9207"))
{
  report = report_fixed_ver(installed_version:deskVer, fixed_version:"9.2 build9229");
  security_message(data:report, port:deskPort);
  exit(0);
}
