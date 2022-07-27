###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_haraka_cmd_inj_vuln.nasl 13561 2019-02-11 07:33:41Z mmartin $
#
# Haraka Command Injection Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:haraka:haraka";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106547");
  script_version("$Revision: 13561 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 08:33:41 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-01-27 12:28:21 +0700 (Fri, 27 Jan 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-1000282");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Haraka Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SMTP problems");
  script_dependencies("gb_haraka_detect.nasl");
  script_mandatory_keys("haraka/installed");

  script_tag(name:"summary", value:"Haraka is prone to a remote command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Haraka comes with a plugin for processing attachments. Versions before
2.8.9 can be vulnerable to command injection.");

  script_tag(name:"affected", value:"Haraka version 2.8.8 and prior.");

  script_tag(name:"solution", value:"Update to 2.8.9 or later versions.");

  script_xref(name:"URL", value:"https://github.com/outflankbv/Exploits/blob/master/harakiri-CVE-2016-1000282.py");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.8.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.9");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
