###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_accellion_fta_multi_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Accellion FTA Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = 'cpe:/h:accellion:secure_file_transfer_appliance';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106074");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-13 11:42:35 +0700 (Fri, 13 May 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2016-2350", "CVE-2016-2351", "CVE-2016-2352", "CVE-2016-2353");

  script_name("Accellion FTA Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_accellion_fta_detect.nasl");
  script_mandatory_keys("accellion_fta/installed");

  script_tag(name:"summary", value:"Accellion FTA is prone to multiple vulnerabilities");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in Accellion File Transfer Appliance:

  - Multiple cross-site scripting (XSS) vulnerabilities in getimageajax.php, move_partition_frame.html and
wmInfo.html (CVE-2016-2350).

  - SQL injection vulnerability in home/seos/courier/security_key2.api via the client_id parameter (CVE-2016-2351).

  - Execution of arbitrary commands by leveraging the YUM_CLIENT restricted-user role (CVE-2016-2352).

  - Allowing local users to add an SSH key to an arbitrary group (CVE-2016-2353).");

  script_tag(name:"impact", value:"Remote unauthenticated attackers may inject arbitrary web scripts or
execute arbitrary SQL commands. Remote authenticated attackers may execute arbitrary commands and local users
gain privileges.");

  script_tag(name:"affected", value:"Accellion FTA Version 9_11_210 and prior.");

  script_tag(name:"solution", value:"Upgrade to version 9_12_40 or later");

  script_xref(name:"URL", value:"http://devco.re/blog/2016/04/21/how-I-hacked-facebook-and-found-someones-backdoor-script-eng-ver/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "9.12.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.12.40");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
