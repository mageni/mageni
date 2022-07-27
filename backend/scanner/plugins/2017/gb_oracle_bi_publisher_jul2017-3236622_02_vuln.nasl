###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_bi_publisher_jul2017-3236622_02_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Oracle BI Publisher Multiple Unspecified Vulnerabilities-02 (jul2017-3236622)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811248");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-10043", "CVE-2017-10035", "CVE-2017-10037", "CVE-2017-10034");
  script_bugtraq_id(99696, 99741, 101334, 101307);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-19 17:26:23 +0530 (Wed, 19 Jul 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle BI Publisher Multiple Unspecified Vulnerabilities-02 (jul2017-3236622)");

  script_tag(name:"summary", value:"This host is installed with Oracle BI Publisher
  and is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to unspecified
  errors in 'BI Publisher Security', 'Web Server', 'Core Formatting API' and
  'Web Service API' components of the application.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to have impact on
  confidentiality and integrity.");

  script_tag(name:"affected", value:"Oracle BI Publisher versions 11.1.1.7.0
  and 11.1.1.9.0");

  script_tag(name:"solution", value:"Apply update from the links mentioned below.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html");

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

if((obpVer == "11.1.1.7.0") || (obpVer == "11.1.1.9.0"))
{
  report = report_fixed_ver(installed_version:obpVer, fixed_version:"Apply Patch");
  security_message(data:report, port:obpPort);
  exit(0);
}
