###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_connect_mult_vuln_feb16.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Adobe Connect Multiple Vulnerabilities Feb16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806868");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2016-0950", "CVE-2016-0949", "CVE-2016-0948");
  script_bugtraq_id(83122, 83120, 83115);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-15 12:26:35 +0530 (Mon, 15 Feb 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe Connect Multiple Vulnerabilities Feb16");

  script_tag(name:"summary", value:"The host is installed with Adobe Connect
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Multiple flaws exist due to

  - An insufficient input validation in a URL parameter.

  - A vulnerability that could be used to misrepresent information presented
    in the user interface.

  - A Cross-Site Request Forgery vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to spoof the user interface, to hijack the authentication of
  unspecified victims and an unspecified impact.");

  script_tag(name:"affected", value:"Adobe Connect versions before 9.5.2");

  script_tag(name:"solution", value:"Upgrade to Adobe Connect version 9.5.2 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/connect/apsb16-07.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_connect_detect.nasl");
  script_mandatory_keys("adobe/connect/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.adobe.com");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!acPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!acVer = get_app_version(cpe:CPE, port:acPort)){
  exit(0);
}

if(version_is_less(version:acVer, test_version:"9.5.2"))
{
  report = report_fixed_ver(installed_version:acVer, fixed_version:"9.5.2");
  security_message(data:report, port:acPort);
  exit(0);
}
