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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142167");
  script_version("2019-03-26T10:36:32+0000");
  script_tag(name:"last_modification", value:"2019-03-26 10:36:32 +0000 (Tue, 26 Mar 2019)");
  script_tag(name:"creation_date", value:"2019-03-26 10:13:52 +0000 (Tue, 26 Mar 2019)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DNS Devices Cr1ptT0r Ransomware");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_dlink_dns_detect.nasl");
  script_mandatory_keys("Host/is_dlink_dns_device");

  script_tag(name:"summary", value:"Multiple D-Link DNS devices are prone to some unknown attacks which are
actively exploited e.g. by the ransomeware Cr1ptT0r.");

  script_tag(name:"impact", value:"Cr1ptT0r ransomware encrypt stored information and then demands payment to
decrypt the information. Other impact might be possible too.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"D-Link DNS-320, DNS-325, DNS-320L and DNS-327L.");

  script_tag(name:"solution", value:"Updated firmware are provided for DNS-320L and DNS-327L. See the referenced
vendor advisory for other solutions.");

  script_xref(name:"URL", value:"https://www.bleepingcomputer.com/news/security/cr1ptt0r-ransomware-infects-d-link-nas-devices-targets-embedded-systems/");
  script_xref(name:"URL", value:"https://securityadvisories.dlink.com/announcement/publication.aspx?name=SAP10110");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:d-link:dns-320",
                     "cpe:/o:d-link:dns-320l",
                     "cpe:/o:d-link:dns-325",
                     "cpe:/o:d-link:dns-327l");

if (!infos = get_all_app_ports_from_list(cpe_list: cpe_list))
  exit(0);

cpe = infos['cpe'];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe == "cpe:/o:d-link:dns-320") {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: 0, data: report);
  exit(0);
}

if (cpe == "cpe:/o:d-link:dns-320l") {
  if (version_is_less(version: version, test_version: "1.11")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.11");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:d-link:dns-325") {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: 0, data: report);
  exit(0);
}

if (cpe == "cpe:/o:d-link:dns-327l") {
  if (version_is_less(version: version, test_version: "1.10")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.10");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);
