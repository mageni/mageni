###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_coldfusion_apsb16-22.nasl 59145 2016-05-16 13:37:56Z May$
#
# Adobe ColdFusion Security Update APSB16-22
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

CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808165");
  script_version("$Revision: 11938 $");
  script_cve_id("CVE-2016-4159");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 12:08:39 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-16 12:39:02 +0530 (Thu, 16 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe ColdFusion Security Update APSB16-22");

  script_tag(name:"summary", value:"This host is running Adobe ColdFusion and is
  prone to reflected cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper input
  validation issue that could be used in reflected cross-site scripting
  attacks.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct cross-site scripting attacks.");

  script_tag(name:"affected", value:"ColdFusion 10 before Update 20 and
  11 before Update 9");

  script_tag(name:"solution", value:"Upgrade to version 10 Update 20 or
  11 Update 9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/coldfusion/apsb16-22.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_coldfusion_detect.nasl");
  script_mandatory_keys("coldfusion/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.adobe.com");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!cfPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!cfdVer = get_app_version(cpe:CPE, port:cfPort)){
  exit(0);
}

if(version_in_range(version:cfdVer, test_version:"10.0", test_version2:"10.0.20.299201"))
{
  fix = "10.0.20.299202";
}
else if(version_in_range(version:cfdVer, test_version:"11.0", test_version2:"11.0.09.299200"))
{
  fix = "11.0.09.299201";
}

if(fix)
{
  report = report_fixed_ver(installed_version:cfdVer, fixed_version:fix);
  security_message(data:report, port:cfPort);
  exit(0);
}
