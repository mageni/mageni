###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cacti_mult_sql_inj_vuln01_apr16_lin.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# Cacti Multiple SQL Injection Vulnerabilities -01 April16 (Linux)
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

CPE = "cpe:/a:cacti:cacti";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807558");
  script_version("$Revision: 11961 $");
  script_cve_id("CVE-2016-3172", "CVE-2016-3659");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-25 18:08:07 +0530 (Mon, 25 Apr 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Cacti Multiple SQL Injection Vulnerabilities -01 April16 (Linux)");

  script_tag(name:"summary", value:"This host is installed with Cacti and is prone to multiple SQL injection
vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to,

  - An insufficient validation of user supplied input passed via HTTP GET parameter 'parent_id' to tree.php
script.

  - An insufficient validation of user supplied input passed via HTTP POST parameter 'host_group_data' to
graph_view.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute arbitrary SQL
commands.");

  script_tag(name:"affected", value:"Cacti versions 0.8.8g and earlier on Linux.");

  script_tag(name:"solution", value:"Update to 0.8.8h or a higher version.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://bugs.cacti.net/view.php?id=2673");
  script_xref(name:"URL", value:"http://bugs.cacti.net/view.php?id=2667");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/136547");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/03/10/13");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cacti_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.cacti.net");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!cacPort = get_app_port(cpe:CPE))
  exit(0);

if(!cactiVer = get_app_version(cpe:CPE, port:cacPort))
  exit(0);

if(version_is_less_equal(version:cactiVer, test_version:"0.8.8g")) {
  report = report_fixed_ver(installed_version:cactiVer, fixed_version:"0.8.8h");
  security_message(data:report, port:cacPort);
  exit(0);
}

exit(0);
