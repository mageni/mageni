###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_splunk_dashboard_xss_vuln_feb15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Splunk Dashboard Cross-Site Scripting Vulnerability - Feb15
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
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

CPE = "cpe:/a:splunk:splunk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805334");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-8302");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-02-05 12:04:16 +0530 (Thu, 05 Feb 2015)");
  script_name("Splunk Dashboard Cross-Site Scripting Vulnerability - Feb15");

  script_tag(name:"summary", value:"The host is installed with Splunk
  and is prone to cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due improper validation of
  user-supplied input passed via the vector related to dashboard.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to execute arbitrary HTML and script code in a user's
  browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Splunk version 5.0.x before 5.0.10
  and 6.0.x before 6.0.6 and 6.1.x before 6.1.4");

  script_tag(name:"solution", value:"Upgrade to Splunk version 5.0.10
  or 6.0.6 or 6.1.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1030994");
  script_xref(name:"URL", value:"http://www.splunk.com/view/SP-CAAANHS#announce2");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_detect.nasl");
  script_mandatory_keys("Splunk/installed");
  script_require_ports("Services/www", 8000);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!splPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!splVer = get_app_version(cpe:CPE, port:splPort)){
    exit(0);
}

if(version_in_range(version: splVer, test_version: "5.0.0", test_version2:"5.0.9"))
{
  fix = "5.0.10";
  VULN = TRUE;
}

if(version_in_range(version: splVer, test_version: "6.0.0", test_version2:"6.0.5"))
{
  fix = "6.0.6";
  VULN = TRUE;
}

if(version_in_range(version: splVer, test_version: "6.1.0", test_version2:"6.1.3"))
{
  fix = "6.1.4";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed version: ' + splVer + '\n' +
           'Fixed version:     ' + fix + '\n';
  security_message(port:splPort, data:report);
  exit(0);
}

exit(99);
