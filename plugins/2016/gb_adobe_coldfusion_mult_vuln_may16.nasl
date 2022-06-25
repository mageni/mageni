###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_coldfusion_mult_vuln_may16.nasl 59145 2016-05-16 13:37:56Z May$
#
# Adobe ColdFusion Multiple Vulnerabilities(may-2016)
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

CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807588");
  script_version("$Revision: 11938 $");
  script_cve_id("CVE-2016-1113", "CVE-2016-1114", "CVE-2016-1115");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 12:08:39 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-16 13:44:30 +0530 (Mon, 16 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe ColdFusion Multiple Vulnerabilities(may-2016)");

  script_tag(name:"summary", value:"This host is running Adobe ColdFusion and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An insufficient validation of user supplied input via unspecified vectors.

  - An important Java deserialization vulnerability in
    Apache Commons Collections library.

  - The mishandling of wildcards in name fields of X.509 certificates.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via unspecified vectors
  and allow man-in-the-middle attackers to spoof servers.");

  script_tag(name:"affected", value:"ColdFusion 10 before Update 19 and
  11 before Update 8");

  script_tag(name:"solution", value:"Upgrade to version 10 Update 19 or
  11 Update 8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/coldfusion/apsb16-16.html");

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

cfdVer = get_app_version(cpe:CPE, port:cfPort);
if(!cfdVer || "unknown" >< cfdVer){
  exit(0);
}

if(version_in_range(version:cfdVer, test_version:"10.0", test_version2:"10.0.19.298510"))
{
  fix = "10.0.19.298511";
}
else if(version_in_range(version:cfdVer, test_version:"11.0", test_version2:"11.0.08.298511"))
{
  fix = "11.0.08.298512";
}

if(fix)
{
  report = report_fixed_ver(installed_version:cfdVer, fixed_version:fix);
  security_message(data:report, port:cfPort);
  exit(0);
}
