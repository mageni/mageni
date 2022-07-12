##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_mult_vuln1.nasl 13532 2019-02-08 07:51:34Z mmartin $
#
# Samba 4.9.x Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:samba:samba";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141731");
  script_version("$Revision: 13532 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 08:51:34 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-11-29 09:59:44 +0700 (Thu, 29 Nov 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2018-16852", "CVE-2018-16857");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Samba 4.9.x Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"summary", value:"Samba is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Samba is prone to multiple vulnerabilities:

  - A user able to create or modify dnsZone objects can crash the Samba AD DC's DNS management RPC server, DNS
    server or BIND9 when using Samba's DLZ plugin (CVE-2018-16852)

  - AD DC Configurations watching for bad passwords (to restrict brute forcing of passwords) in a window of more
    than 3 minutes may not watch for bad passwords at all. (CVE-2018-16857)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Samba 4.9.x before 4.9.3.");

  script_tag(name:"solution", value:"Update to version 4.9.3 or later.");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2018-16852.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2018-16857.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path    = infos['location'];

if (version_in_range(version: version, test_version: "4.9.0", test_version2: "4.9.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.3", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
