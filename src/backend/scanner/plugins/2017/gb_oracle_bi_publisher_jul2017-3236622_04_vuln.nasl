###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_bi_publisher_jul2017-3236622_04_vuln.nasl 11962 2018-10-18 10:51:32Z mmartin $
#
# Oracle BI Publisher Multiple Unspecified Vulnerabilities-04 (jul2017-3236622)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:oracle:business_intelligence_publisher";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811250");
  script_version("$Revision: 11962 $");
  script_cve_id("CVE-2017-10041", "CVE-2016-3092");
  script_bugtraq_id(99742, 91453);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:51:32 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-19 17:54:23 +0530 (Wed, 19 Jul 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle BI Publisher Multiple Unspecified Vulnerabilities-04 (jul2017-3236622)");

  script_tag(name:"summary", value:"This host is installed with Oracle BI Publisher
  and is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to unspecified
  errors in 'Web Server' component of the application.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to have an impact on
  confidentiality and integrity.");

  script_tag(name:"affected", value:"Oracle BI Publisher versions 11.1.1.9.0,
  12.2.1.1.0 and 12.2.1.2.0");

  script_tag(name:"solution", value:"Apply update from the link mentioned below.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_oracle_bi_publisher_detect.nasl");
  script_mandatory_keys("Oracle/BI/Publisher/Enterprise/installed");
  script_require_ports("Services/www", 9704);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!obpPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!obpVer = get_app_version(cpe:CPE, port:obpPort)){
  exit(0);
}

if((obpVer == "11.1.1.9.0") || (obpVer == "12.2.1.1.0") || (obpVer == "12.2.1.2.0"))
{
  report = report_fixed_ver(installed_version:obpVer, fixed_version:"Apply Patch");
  security_message(data:report, port:obpPort);
  exit(0);
}
exit(0);
