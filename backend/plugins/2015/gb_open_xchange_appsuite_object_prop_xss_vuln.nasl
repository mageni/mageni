###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_xchange_appsuite_object_prop_xss_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Open-Xchange (OX) AppSuite Object Properties Cross Site Scripting Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806525");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-5375");
  script_bugtraq_id(76837);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-02 12:36:19 +0530 (Mon, 02 Nov 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Open-Xchange (OX) AppSuite Object Properties Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with
  Open-Xchange (OX) AppSuite and is prone to cross site scripting
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insufficient
  sanitization of user supplied input via unknown vectors related to object
  properties.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML in the browser of an
  unsuspecting user in the context of the affected site.");

  script_tag(name:"affected", value:"Open-Xchange (OX) AppSuite versions
  before 6.22.8-rev8, 6.22.9 before 6.22.9-rev15, 7.x before 7.6.1-rev25, and
  7.6.2 before 7.6.2-rev20.");

  script_tag(name:"solution", value:"Upgrade to Open-Xchange (OX) AppSuite
  version 6.22.8-rev8 or 6.22.9-rev15 or 7.6.1-rev25 or 7.6.2-rev20 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/536523/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

oxVer = get_app_version(cpe:CPE, port:oxPort);
if(!oxVer || "unknown" >< oxVer){
  exit(0);
}

oxRev = get_kb_item("open_xchange_appsuite/" + oxPort + "/revision");

if(oxRev)
{
  ## Updating version with revision number
  oxVer = oxVer + "." + oxRev;

  if(version_is_less(version:oxVer, test_version:"6.22.8.8"))
  {
    fix = "6.22.8-rev8";
    VULN = TRUE;
  }

  if(version_in_range(version:oxVer, test_version:"6.22.9", test_version2:"6.22.9.14"))
  {
    fix = "6.22.9-rev15";
    VULN = TRUE;
  }

  if(version_in_range(version:oxVer, test_version:"7.6.1", test_version2:"7.6.1.24"))
  {
    fix = "7.6.1-rev25";
    VULN = TRUE;
  }

  if(version_in_range(version:oxVer, test_version:"7.6.2", test_version2:"7.6.2.19"))
  {
    fix = "7.6.2-rev20";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = 'Installed Version: ' + oxVer + '\nFixed Version:     ' + fix + '\n';
    security_message(data:report, port:oxPort);
    exit(0);
  }
}

exit(99);