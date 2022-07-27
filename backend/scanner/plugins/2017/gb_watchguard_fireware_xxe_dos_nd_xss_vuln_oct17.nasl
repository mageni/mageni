###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_watchguard_fireware_xxe_dos_nd_xss_vuln_oct17.nasl 11901 2018-10-15 08:47:18Z mmartin $
#
# WatchGuard Fireware XTM XXE DOS and Stored XSS Vulnerabilities
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/o:watchguard:fireware';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811910");
  script_version("$Revision: 11901 $");
  script_cve_id("CVE-2017-14615", "CVE-2017-14616");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-15 10:47:18 +0200 (Mon, 15 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-04 13:28:50 +0530 (Wed, 04 Oct 2017)");
  script_name("WatchGuard Fireware XTM XXE DOS and Stored XSS Vulnerabilities");

  script_tag(name:"summary", value:"This host is running WatchGuard Fireware XMT
  Web UI is prone to XXE DOS and stored XSS  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - When a failed login attempt is made to the login endpoint of the XML-RPC
    interface, if javascript code, properly encoded to be consumed by XML
    parsers, is embedded as value of the user tag, the code will be rendered
    in the context of any logged in user in the Web UI visiting
    'Traffic Monitor' sections 'Events' and 'All'.

  - If a login attempt is made in the XML-RPC interface with a XML message
    containing and empty member tag, the wgagent crashes logging out any user
    with a session opened in the UI. By continuously executing the failed
    logging attempts, the device will be impossible to be managed using the UI.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities
  allow an attacker to inject arbitrary JavaScript into the Firebox log messages,
  which could impact users of the Web UI Traffic Monitor.");

  script_tag(name:"affected", value:"WatchGuard Fireware before 12.0");

  script_tag(name:"solution", value:"Upgrade to WatchGuard Fireware 12.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2017/Sep/22");
  script_xref(name:"URL", value:"https://watchguardsupport.secure.force.com/publicKB?type=KBSecurityIssues&SFDCID=kA62A0000000L0HSAU&lang=en_US");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_watchguard_fireware_detect.nasl", "gb_snmp_os_detection.nasl");
  script_mandatory_keys("watchguard_fireware/installed");
  script_xref(name:"URL", value:"http://tomcat.apache.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!watchPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!version = get_app_version(cpe:CPE, port:watchPort)){
  exit(0);
}

if(version_is_less(version:version, test_version: "12.0"))
{
  report = report_fixed_ver(installed_version:version, fixed_version:"12.0");
  security_message(port:watchPort, data: report);
  exit(0);
}
exit(0);
