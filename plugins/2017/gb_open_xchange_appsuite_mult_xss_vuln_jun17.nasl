###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_xchange_appsuite_mult_xss_vuln_jun17.nasl 11816 2018-10-10 10:42:56Z mmartin $
#
# Open-Xchange (OX) AppSuite Multiple Cross Site Scripting Vulnerabilities Jun17
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:open-xchange:open-xchange_appsuite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811134");
  script_version("$Revision: 11816 $");
  script_cve_id("CVE-2015-1588");
  script_bugtraq_id(74350);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 12:42:56 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-21 16:24:33 +0530 (Wed, 21 Jun 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Open-Xchange (OX) AppSuite Multiple Cross Site Scripting Vulnerabilities Jun17");

  script_tag(name:"summary", value:"The host is installed with
  Open-Xchange (OX) AppSuite and is prone to multiple xss vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the sanitation and
  cleaner engine does not properly filter HTML code from user-supplied input
  before displaying the input. A remote user can cause arbitrary scripting
  code to be executed by the target user's browser.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML in the browser of an
  unsuspecting user. This can lead to session hijacking or triggering unwanted
  actions via the web interface (sending mail, deleting data etc.). Potential
  attack vectors are E-Mail (via attachments) or Drive.");

  script_tag(name:"affected", value:"Open-Xchange (OX) AppSuite versions
  7.6.1-rev0 - 7.6.1-rev20,
  7.6.0-rev0 - 7.6.0-rev37,
  7.4.2-rev42 and prior.");

  script_tag(name:"solution", value:"Upgrade to Open-Xchange (OX) AppSuite
  version 7.4.2-rev43, 7.6.0-rev38, 7.6.1-rev21, or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/535388/100/1100/threaded");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ox_app_suite_detect.nasl");
  script_mandatory_keys("open_xchange_appsuite/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://www.open-xchange.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!oxPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!oxVer = get_app_version(cpe:CPE, port:oxPort)){
  exit(0);
}

oxRev = get_kb_item("open_xchange_appsuite/" + oxPort + "/revision");

if(oxRev)
{
  ## Updating version with revision number
  oxVer = oxVer + "." + oxRev;

  if(version_is_less( version:oxVer, test_version:"7.4.2.43")){
    fix = "7.4.2-rev43";
  }

  else if(oxVer =~ "^(7\.6\.0)" && version_is_less( version:oxVer, test_version:"7.6.0.38")){
    fix = "7.6.0-rev38";
  }

  else if(oxVer =~ "^(7\.6\.1)" && version_is_less( version:oxVer, test_version:"7.6.1.21")){
    fix = "7.6.1-rev21";
  }
  if(fix)
  {
    report = report_fixed_ver(installed_version:oxVer, fixed_version:fix);
    security_message(port:oxPort, data:report);
    exit(0);
  }
}

exit(99);