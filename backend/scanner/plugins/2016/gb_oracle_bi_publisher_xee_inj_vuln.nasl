###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_bi_publisher_xee_inj_vuln.nasl 12323 2018-11-12 15:36:30Z cfischer $
#
# Oracle BI Publisher XML External Entity Injection Vulnerability
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

CPE = "cpe:/a:oracle:business_intelligence_publisher";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809733");
  script_version("$Revision: 12323 $");
  script_cve_id("CVE-2016-3473");
  script_bugtraq_id(93719);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 16:36:30 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-25 17:10:49 +0530 (Fri, 25 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle BI Publisher XML External Entity Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Oracle BI Publisher
  and is prone to XML external entity injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the 'Security'
  sub-component of Oracle BI Publisher.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to conduct XML External Entity (XXE) injection attack
  on the affected system.");

  script_tag(name:"affected", value:"Oracle BI Publisher versions 11.1.1.7.0,
  11.1.1.9.0, 12.2.1.0.0");

  script_tag(name:"solution", value:"Apply the update from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40590");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(version_is_equal(version:obpVer, test_version:"11.1.1.7.0")||
   version_is_equal(version:obpVer, test_version:"11.1.1.9.0")||
   version_is_equal(version:obpVer, test_version:"12.2.1.0.0"))
{
  report = report_fixed_ver(installed_version:obpVer, fixed_version:"Apply Patch");
  security_message(data:report, port:obpPort);
  exit(0);
}
