###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_web_jetadmin_security_bypass_vuln_win.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# HP Web Jetadmin Unspecified Local Security Bypass Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.812517");
  script_version("$Revision: 12116 $");
  script_cve_id("CVE-2011-0278");
  script_bugtraq_id(46595);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-20 17:10:32 +0530 (Tue, 20 Feb 2018)");
  script_name("HP Web Jetadmin Unspecified Local Security Bypass Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with HP Web Jetadmin
  and is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in HP Web
  JetAdmin.

  No details are available.");

  script_tag(name:"impact", value:"Successfully exploitation will allow an
  attacker to gain unauthorized access to certain resources. This may aid
  in further attacks.");

  script_tag(name:"affected", value:"HP Web Jetadmin versions 10.2 SR3/SR4 on Windows");

  script_tag(name:"solution", value:"Upgrade to version 10.2 SR5 or later.");

  script_xref(name:"URL", value:"https://securitytracker.com/id?1025130");
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

# HP Web Jetadmin 10.2 SR3->10.2.66860
# HP Web Jetadmin 10.2 SR4->10.2.71771
if(jetVers == "10.2.66860" || jetVers == "10.2.71771"){
  report = report_fixed_ver(installed_version:jetVers, fixed_version:"10.2 SR5 ", install_path:path);
  security_message(port:jetPort, data:report);
  exit(0);
}

exit(99);
