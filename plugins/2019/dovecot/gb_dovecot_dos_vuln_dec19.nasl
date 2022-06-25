# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:dovecot:dovecot";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114165");
  script_version("2019-12-16T11:08:47+0000");
  script_tag(name:"last_modification", value:"2019-12-16 11:08:47 +0000 (Mon, 16 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-16 11:52:38 +0100 (Mon, 16 Dec 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2019-19722");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dovecot < 2.3.9.2 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_dovecot_consolidation.nasl");
  script_mandatory_keys("dovecot/detected");

  script_tag(name:"summary", value:"Dovecot is prone to a denial of service vulnerability.");

  script_tag(name:"insight", value:"An attacker can crash a push-notification driver with a
  crafted email when push notifications are used, because of a NULL pointer dereference. The
  email must use a group address as either the sender or the recipient.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Dovecot prior to version 2.3.9.2.");

  script_tag(name:"solution", value:"Update to version 2.3.9.2 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/12/13/3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if(version_is_less(version: version, test_version: "2.3.9.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.9.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
