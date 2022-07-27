# Copyright (C) 2020 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.#

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143567");
  script_version("2020-02-28T06:22:57+0000");
  script_tag(name:"last_modification", value:"2020-03-03 11:02:28 +0000 (Tue, 03 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-02-28 05:16:06 +0000 (Fri, 28 Feb 2020)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2020-9330");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Xerox WorkCentre Printers LDAP Information Disclosure Vulnerability (XRX20D)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_xerox_printer_consolidation.nasl");
  script_mandatory_keys("xerox_printer/detected");

  script_tag(name:"summary", value:"Xerox WorkCentre printers are prone to an information disclosure vulnerability
  over LDAP.");

  script_tag(name:"insight", value:"Certain Xerox WorkCentre printers do not require the user to reenter or
  validate LDAP bind credentials when changing the LDAP connector IP address. A malicious actor who gains access
  to affected devices (e.g., by using default credentials) can change the LDAP connection IP address to a system
  owned by the actor without knowledge of the LDAP bind credentials. After changing the LDAP connection IP address,
  subsequent authentication attempts will result in the printer sending plaintext LDAP (Active Directory)
  credentials to the actor. Although the credentials may belong to a non-privileged user, organizations frequently
  use privileged service accounts to bind to Active Directory. The attacker gains a foothold on the Active
  Directory domain at a minimum, and may use the credentials to take over control of the Active Directory domain.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"affected", value:"WorkCentre 3655, 3655i, 58XX, 58XXi, 59XX, 59XXi, 6655, 6655i, 72XX, 72XXi,
  78XX, 78XXi, 7970, 7970i, EC7836, and EC7856 devices.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://securitydocs.business.xerox.com/wp-content/uploads/2020/02/cert_Security_Mini_Bulletin_XRX20D_for_ConnectKey.pdf");
  script_xref(name:"URL", value:"https://www.securicon.com/hackers-can-gain-active-directory-privileges-through-new-vulnerability-in-xerox-printers/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:xerox:workcentre_3655_firmware",
                     "cpe:/o:xerox:workcentre_3655i_firmware",
                     "cpe:/o:xerox:workcentre_5845_firmware",
                     "cpe:/o:xerox:workcentre_5855_firmware",
                     "cpe:/o:xerox:workcentre_5865_firmware",
                     "cpe:/o:xerox:workcentre_5865i_firmware",
                     "cpe:/o:xerox:workcentre_5875_firmware",
                     "cpe:/o:xerox:workcentre_5875i_firmware",
                     "cpe:/o:xerox:workcentre_5890_firmware",
                     "cpe:/o:xerox:workcentre_5890i_firmware",
                     "cpe:/o:xerox:workcentre_5945_firmware",
                     "cpe:/o:xerox:workcentre_5945i_firmware",
                     "cpe:/o:xerox:workcentre_5955_firmware",
                     "cpe:/o:xerox:workcentre_5955i_firmware",
                     "cpe:/o:xerox:workcentre_6655_firmware",
                     "cpe:/o:xerox:workcentre_6655i_firmware",
                     "cpe:/o:xerox:workcentre_7220_firmware",
                     "cpe:/o:xerox:workcentre_7220i_firmware",
                     "cpe:/o:xerox:workcentre_7225_firmware",
                     "cpe:/o:xerox:workcentre_7225i_firmware",
                     "cpe:/o:xerox:workcentre_7830_firmware",
                     "cpe:/o:xerox:workcentre_7830i_firmware",
                     "cpe:/o:xerox:workcentre_7835_firmware",
                     "cpe:/o:xerox:workcentre_7835i_firmware",
                     "cpe:/o:xerox:workcentre_7845_firmware",
                     "cpe:/o:xerox:workcentre_7845i_firmware",
                     "cpe:/o:xerox:workcentre_7855_firmware",
                     "cpe:/o:xerox:workcentre_7855i_firmware",
                     "cpe:/o:xerox:workcentre_7970_firmware",
                     "cpe:/o:xerox:workcentre_7970i_firmware",
                     "cpe:/o:xerox:workcentre_ec7836_firmware",
                     "cpe:/o:xerox:workcentre_ex7856_firmware");

if (!infos = get_all_app_ports_from_list(cpe_list: cpe_list))
  exit(0);

cpe = infos['cpe'];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe == "cpe:/o:xerox:workcentre_3655_firmware" || cpe == "cpe:/o:xerox:workcentre_3655i_firmware") {
  if (version_is_less(version: version, test_version: "073.060.000.02300")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.060.000.02300");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_5845_firmware" || cpe == "cpe:/o:xerox:workcentre_5855_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_5865_firmware" || cpe == "cpe:/o:xerox:workcentre_5875_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_5890_firmware" || cpe == "cpe:/o:xerox:workcentre_5865i_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_5875i_firmware" || cpe == "cpe:/o:xerox:workcentre_5890i_firmware") {
  if (version_is_less(version: version, test_version: "073.190.000.02300")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.190.000.02300");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_5945_firmware" || cpe == "cpe:/o:xerox:workcentre_5945i_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_5955_firmware" || cpe == "cpe:/o:xerox:workcentre_5945i_firmware") {
  if (version_is_less(version: version, test_version: "073.091.000.02300")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.091.000.02300");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_6655_firmware" || cpe == "cpe:/o:xerox:workcentre_6655i_firmware") {
  if (version_is_less(version: version, test_version: "073.110.000.02300")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.110.000.02300");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_7220_firmware" || cpe == "cpe:/o:xerox:workcentre_7220i_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_7225_firmware" || cpe == "cpe:/o:xerox:workcentre_7225i_firmware") {
  if (version_is_less(version: version, test_version: "073.030.000.02300")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.030.000.02300");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_7830_firmware" || cpe == "cpe:/o:xerox:workcentre_7830i_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_7835_firmware" || cpe == "cpe:/o:xerox:workcentre_7835i_firmware") {
  if (version_is_less(version: version, test_version: "073.010.000.02300")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.010.000.02300");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_7845_firmware" || cpe == "cpe:/o:xerox:workcentre_7845i_firmware" ||
    cpe == "cpe:/o:xerox:workcentre_7855_firmware" || cpe == "cpe:/o:xerox:workcentre_7855i_firmware") {
  if (version_is_less(version: version, test_version: "073.040.000.02300")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.040.000.02300");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_7970_firmware" || cpe == "cpe:/o:xerox:workcentre_7970i_firmware") {
  if (version_is_less(version: version, test_version: "073.200.000.02300")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.200.000.02300");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_ec7836_firmware") {
  if (version_is_less(version: version, test_version: "073.050.000.02300")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.050.000.02300");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:xerox:workcentre_ec7856_firmware") {
  if (version_is_less(version: version, test_version: "073.020.000.02300")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "073.020.000.02300");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
