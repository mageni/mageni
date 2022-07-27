###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_mysql_multiple_vuln01_nov12_lin.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Oracle MySQL Server Multiple Vulnerabilities-01 Nov12 (Linux)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812190");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2012-3197", "CVE-2012-3163", "CVE-2012-3158", "CVE-2012-3150");
  script_bugtraq_id(56036, 56017, 55990, 56005);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-22 19:08:06 +0530 (Wed, 22 Nov 2017)");
  script_name("Oracle MySQL Server Multiple Vulnerabilities-01 Nov12 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51008/");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/51008");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html");
  script_xref(name:"URL", value:"https://support.oracle.com/rs?type=doc&id=1475188.1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed", "Host/runs_unixoide");
  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to disclose potentially sensitive information, manipulate certain
  data and cause a DoS (Denial of Service).");

  script_tag(name:"affected", value:"Oracle MySQL version 5.1.x to 5.1.64 and
  Oracle MySQL version 5.5.x to 5.5.26 on windows");

  script_tag(name:"insight", value:"The flaws are due to multiple unspecified
  errors in MySQL server component related to server replication, information
  schema, protocol and server optimizer.");

  script_tag(name:"solution", value:"Apply the patch or upgrade to latest
  version.");

  script_tag(name:"summary", value:"The host is running Oracle MySQL server
  and is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("misc_func.inc");
include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE)) exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:sqlPort, exit_no_version:TRUE)) exit(0);
mysqlVer = infos['version'];
mysqlPath = infos['location'];

mysqlVer = eregmatch(pattern:"([0-9.a-z]+)", string:mysqlVer);

if(mysqlVer[1])
{
  ## Oracle MySQL version 5.1.x to 5.1.64 and 5.5.x to 5.5.26
  if(version_in_range(version:mysqlVer[1], test_version:"5.1.0", test_version2:"5.1.64") ||
     version_in_range(version:mysqlVer[1], test_version:"5.5.0 ", test_version2:"5.5.26"))
  {
    report = report_fixed_ver( installed_version:mysqlVer[1], fixed_version: "Apply the patch", install_path:mysqlPath );
    security_message(data:report, port:sqlPort);
    exit(0);
  }
}
