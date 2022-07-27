###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pfsense_rce_vuln.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# pfSense Remote Code Execution & Cross-Site Request Forgery Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:pfsense:pfsense";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112135");
  script_version("$Revision: 11977 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-23 08:35:21 +0100 (Thu, 23 Nov 2017)");
  script_name("pfSense Remote Code Execution & Cross-Site Request Forgery Vulnerability");

  script_cve_id("CVE-2017-1000479");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");

  script_tag(name:"summary", value:"This host is running pfSense and is prone
to a remote code execution and cross-site request forgery (csrf) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The pfSense WebGUI is vulnerable to clickjacking.
By tricking an authenticated admin into interacting with a specially crafted webpage it is possible for an attacker
to execute arbitrary code in the WebGUI.");

  script_tag(name:"impact", value:"Since the WebGUI runs as the root user, this will result in a full compromise of the pfSense instance.");

  script_tag(name:"affected", value:"pfSense before version 2.4.2");

  script_tag(name:"solution", value:"Upgrade to version 2.4.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.securify.nl/advisory/SFY20171101/clickjacking-vulnerability-in-csrf-error-page-pfsense.html");
  script_xref(name:"URL", value:"https://doc.pfsense.org/index.php/2.4.2_New_Features_and_Changes");
  script_xref(name:"URL", value:"https://www.netgate.com/blog/pfsense-2-4-2-release-p1-and-2-3-5-release-p1-now-available.html");

  script_dependencies("gb_pfsense_detect.nasl");
  script_mandatory_keys("pfsense/installed");

  script_xref(name:"URL", value:"https://www.pfsense.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ver = get_app_version(cpe:CPE, nofork:TRUE)) exit(0);

if(version_is_less(version:ver, test_version:"2.4.2"))
{
  report = report_fixed_ver(installed_version:ver, fixed_version:"2.4.2-RELEASE");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
