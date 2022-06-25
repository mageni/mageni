###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_xchange_appsuite_mult_vuln01.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Open-Xchange (OX) AppSuite Multiple Vulnerabilities -01 Oct15
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
  script_oid("1.3.6.1.4.1.25623.1.0.806068");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-5234", "CVE-2014-5235");
  script_bugtraq_id(69796, 69792);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-05 16:02:56 +0530 (Mon, 05 Oct 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Open-Xchange (OX) AppSuite Multiple Vulnerabilities -01 Oct15");

  script_tag(name:"summary", value:"The host is installed with
  Open-Xchange (OX) AppSuite and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Insufficient sanitization of user-supplied input via a
    folder publication name.

  - Insufficient sanitization of user-supplied input via vectors related to
    unspecified fields in RSS feeds");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary HTML and script code in a user's browser session in the
  context of of the affected site, potentially allowing the attacker to steal
  cookie-based authentication credentials and control how the site is rendered
  to the user, other attacks are also possible.");

  script_tag(name:"affected", value:"Open-Xchange (OX) AppSuite versions before
  7.4.2-rev33 and 7.6.x before 7.6.0-rev16");

  script_tag(name:"solution", value:"Upgrade to Open-Xchange (OX) AppSuite
  version 7.4.2-rev33 or 7.6.0-rev16 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/128257");
  script_xref(name:"URL", value:"http://www.securiteam.com/cves/2014/CVE-2014-5234.html");
  script_xref(name:"URL", value:"http://www.securiteam.com/cves/2014/CVE-2014-5235.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/533443/100/0/threaded");

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

if(oxRev){

  ## Updating version with revision number
  oxVer = oxVer + "." + oxRev;

  if(version_is_less( version:oxVer, test_version:"7.4.2.33" ))
  {
    fix = "7.4.2-rev33";
    VULN = TRUE;
  }

  else if(oxVer =~ "^(7\.6)")
  {
    if(version_is_less( version:oxVer, test_version:"7.6.0.16" ))
    {
      fix = "7.6.0-rev16";
      VULN = TRUE;
    }
  }

  if(VULN)
  {
    report = 'Installed Version: ' + oxVer + '\nFixed Version:     ' + fix + '\n';
    security_message(port:oxPort, data:report);
    exit(0);
  }
}

exit(99);