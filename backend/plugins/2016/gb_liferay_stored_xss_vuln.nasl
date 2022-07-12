###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_liferay_stored_xss_vuln.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# Liferay Stored XSS Vulnerability
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:liferay:liferay_portal";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808707");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-3670");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-08-01 13:53:02 +0530 (Mon, 01 Aug 2016)");
  script_name("Liferay Stored XSS Vulnerability");

  script_tag(name:"summary", value:"This host is running Liferay and is prone to
  stored xss vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation
  of user input in 'users.jsp' script.");

  script_tag(name:"impact", value:"Successfully exploitation will allows remote
  attackers to inject arbitrary web script or HTML via the FirstName field.");

  script_tag(name:"affected", value:"Liferay version before 7.0.0 CE RC1.");

  script_tag(name:"solution", value:"Update Liferay version 7.0.0 CE RC1
  and later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://labs.integrity.pt/advisories/cve-2016-3670/");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_liferay_detect.nasl");
  script_mandatory_keys("Liferay/Installed");
  script_xref(name:"URL", value:"https://issues.liferay.com/browse/LPS/component/10296");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!lifePort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!lifeVer = get_app_version(cpe:CPE, port:lifePort)){
  exit(0);
}

if(version_is_less(version:lifeVer, test_version:"7.0.0.CE.RC1"))
{
  report =  report_fixed_ver(installed_version:lifeVer, fixed_version:"7.0.0 CE RC1");
  security_message(data:report, port:lifePort);
  exit(0);
}
