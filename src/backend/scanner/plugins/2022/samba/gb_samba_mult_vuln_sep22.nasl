# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104323");
  script_version("2022-09-15T10:11:07+0000");
  script_tag(name:"last_modification", value:"2022-09-15 10:11:07 +0000 (Thu, 15 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-15 07:23:25 +0000 (Thu, 15 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");

  script_cve_id("CVE-2022-1615", "CVE-2022-32743");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Samba Multiple Vulnerabilities (Sep 2022)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"summary", value:"Samba is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2022-1615: In Samba, GnuTLS gnutls_rnd() can fail and give predictable random values.

  - CVE-2022-32743: Samba does not validate the Validated-DNS-Host-Name right for the dNSHostName
  attribute which could permit unprivileged users to write it.");

  # TODO: Re-check once the advisories have been published
  script_tag(name:"affected", value:"Samba versions starting from 4.1 and prior to 4.17.0.");

  script_tag(name:"solution", value:"Update to version 4.17.0 or later.");

  script_xref(name:"URL", value:"https://bugzilla.samba.org/show_bug.cgi?id=15103");
  script_xref(name:"URL", value:"https://gitlab.com/samba-team/samba/-/merge_requests/2644");
  script_xref(name:"URL", value:"https://bugzilla.samba.org/show_bug.cgi?id=14833");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "4.1.0", test_version_up: "4.17.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.17.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
