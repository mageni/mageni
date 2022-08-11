###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_web_jetadmin_mult_xss_vuln_win.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# HP Web Jetadmin Multiple Cross-Site Scripting Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:hp:web_jetadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812518");
  script_version("$Revision: 12116 $");
  script_cve_id("CVE-2012-2011");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-20 17:30:33 +0530 (Tue, 20 Feb 2018)");
  script_name("HP Web Jetadmin Multiple Cross-Site Scripting Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"This host is installed with HP Web Jetadmin
  and is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The software does not properly filter HTML
  code from user-supplied input before displaying the input. A remote user can
  cause arbitrary scripting code to be executed by the target users browser.");

  script_tag(name:"impact", value:"Successfully exploitation will allow an
  attacker to inject arbitrary web script or HTML via unspecified vectors.");

  script_tag(name:"affected", value:"HP Web Jetadmin versions 8.x on Windows");

  script_tag(name:"solution", value:"Upgrade to version 10.x or later.");

  script_xref(name:"URL", value:"https://www.securitytracker.com/id?1027138");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("gb_hp_web_jetadmin_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8000);
  script_mandatory_keys("HpWebJetadmin/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www8.hp.com/us/en/solutions/business-solutions/printingsolutions/wja.html");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!jetPort = get_app_port(cpe:CPE)) exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:jetPort, exit_no_version:TRUE)) exit(0);
jetVers = infos['version'];
path = infos['location'];

if(jetVers =~ "^8\.0"){
  report = report_fixed_ver(installed_version:jetVers, fixed_version:"10.x", install_path:path);
  security_message(port:jetPort, data:report);
  exit(0);
}

exit(99);
