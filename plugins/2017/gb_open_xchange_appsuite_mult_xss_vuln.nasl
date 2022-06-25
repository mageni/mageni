###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_xchange_appsuite_mult_xss_vuln.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# Open-Xchange (OX) AppSuite Multiple Cross Site Scripting Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.809849");
  script_version("$Revision: 11982 $");
  script_cve_id("CVE-2016-5740");
  script_bugtraq_id(92922);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-02 15:30:26 +0530 (Mon, 02 Jan 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Open-Xchange (OX) AppSuite Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with
  Open-Xchange (OX) AppSuite and is prone to multiple xss vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an improper
  sanitization of user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary script code in the browser of an unsuspecting user in the
  context of the affected application. This may let the attacker steal cookie-based
  authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Open-Xchange (OX) AppSuite versions
  7.6.2-rev0 - 7.6.2-rev57,
  7.6.3-rev0 - 7.6.3-rev13,
  7.8.0-rev0 - 7.8.0-rev35,
  7.8.1-rev0 - 7.8.1-rev17,
  7.8.2-rev0 - 7.8.2-rev4");

  script_tag(name:"solution", value:"Upgrade to Open-Xchange (OX) AppSuite
  version 7.6.2-rev58, 7.6.3-rev14, 7.8.0-rev36, 7.8.1-rev18, 7.8.2-rev5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40378");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/138700");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/539394/100/0/threaded");

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

  if(oxVer =~ "^(7\.8\.1)" && version_is_less( version:oxVer, test_version:"7.8.1.18"))
  {
    fix = "7.8.1-rev18";
    VULN = TRUE;
  }

  else if(oxVer =~ "^(7\.6\.2)" && version_is_less( version:oxVer, test_version:"7.6.2.58"))
  {
    fix = "7.6.2-rev58";
    VULN = TRUE;
  }

  else if(oxVer =~ "^(7\.6\.3)" && version_is_less( version:oxVer, test_version:"7.6.3.14"))
  {
    fix = "7.6.3-rev14";
    VULN = TRUE;
  }

  else if(oxVer =~ "^(7\.8\.0)" && version_is_less( version:oxVer, test_version:"7.8.0.36"))
  {
    fix = "7.8.0-rev36";
    VULN = TRUE;
  }

  else if(oxVer =~ "^(7\.8\.2)" && version_is_less( version:oxVer, test_version:"7.8.2.5"))
  {
    fix = "7.8.2-rev5";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:oxVer, fixed_version:fix);
    security_message(port:oxPort, data:report);
    exit(0);
  }
}

exit(99);