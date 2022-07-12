###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_coldfusion_mult_vuln.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Adobe ColdFusion Multiple Vulnerabilities(march-2016)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807014");
  script_version("$Revision: 12149 $");
  script_cve_id("CVE-2015-8052", "CVE-2015-8053", "CVE-2015-5255");
  script_bugtraq_id(77625, 77626);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-11 14:43:52 +0530 (Fri, 11 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe ColdFusion Multiple Vulnerabilities(march-2016)");

  script_tag(name:"summary", value:"This host is running Adobe ColdFusion and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An insufficient validation of user supplied input via unspecified vectors.

  - The Server-Side Request Forgery (SSRF) issue in Adobe BlazeDS.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via unspecified vectors,
  to send HTTP traffic to intranet servers.");

  script_tag(name:"affected", value:"ColdFusion 10 before Update 18 and
  11 before Update 7");

  script_tag(name:"solution", value:"Upgrade to version 10 Update 18 or
  11 Update 7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/coldfusion/apsb15-29.html");

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

if(version_in_range(version:cfdVer, test_version:"10.0", test_version2:"10.0.18.296329"))
{
  fix = "10.0.18.296330";
}
else if(version_in_range(version:cfdVer, test_version:"11.0", test_version2:"11.0.07.296329"))
{
  fix = "11.0.07.296330";
}

if(fix)
{
  report = report_fixed_ver(installed_version:cfdVer, fixed_version:fix);
  security_message(data:report, port:cfPort);
  exit(0);
}

exit(99);