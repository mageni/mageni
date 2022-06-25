###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_junos_space_JSA10760.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Junos Space Multiple Vulnerabilities
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

CPE = "cpe:/a:juniper:junos_space";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106348");
  script_version("$Revision: 12313 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-13 09:18:34 +0700 (Thu, 13 Oct 2016)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2016-4926", "CVE-2016-4927", "CVE-2016-4928", "CVE-2016-4929", "CVE-2016-4930",
"CVE-2016-4931");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Junos Space Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_junos_space_version.nasl");
  script_mandatory_keys("junos_space/installed");

  script_tag(name:"summary", value:"Junos Space is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Junos Space is prone to multiple vulnerabilities:

  - Insufficient authentication vulnerability in Junos Space may allow remote network based users with access to
Junos Space web interface to perform certain administrative tasks without authentication. (CVE-2016-4926)

  - Insufficient validation of SSH keys in Junos Space may allow man-in-the-middle (MITM) type of attacks while a
Space device is communicating with managed devices. (CVE-2016-4927)

  - Cross site request forgery vulnerability in Junos Space may allow remote attackers to perform certain
administrative actions on Junos Space. (CVE-2016-4928)

  - Command injection vulnerability in Junos Space may allow unprivileged users to execute code as root user on
the device. (CVE-2016-4929)

  - Cross site scripting vulnerability may allow remote attackers to steal sensitive information or perform certain
administrative actions on Junos Space. (CVE-2016-4930)

  - XML entity injection vulnerability may allow unprivileged users to cause a denial of service condition.
(CVE-2016-4931)");

  script_tag(name:"affected", value:"This issue can affect any product or platform running Junos Space before
15.2R2.");

  script_tag(name:"solution", value:"Update to version 15.2R2 or later.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10760");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("junos.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (check_js_version(ver: version, fix: "15.2R2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.2R2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
