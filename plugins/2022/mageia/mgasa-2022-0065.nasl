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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0065");
  script_cve_id("CVE-2021-0066", "CVE-2021-0072", "CVE-2021-0076", "CVE-2021-0161", "CVE-2021-0164", "CVE-2021-0165", "CVE-2021-0166", "CVE-2021-0168", "CVE-2021-0170", "CVE-2021-0172", "CVE-2021-0173", "CVE-2021-0174", "CVE-2021-0175", "CVE-2021-0176", "CVE-2021-33139", "CVE-2021-33155");
  script_tag(name:"creation_date", value:"2022-02-16 03:20:56 +0000 (Wed, 16 Feb 2022)");
  script_version("2022-02-16T15:36:35+0000");
  script_tag(name:"last_modification", value:"2022-02-17 11:13:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-14 19:33:00 +0000 (Mon, 14 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0065)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0065");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0065.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30038");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00539.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00604.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-firmware-nonfree, radeon-firmware' package(s) announced via the MGASA-2022-0065 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides new and updated nonfree firmwares and fixes at least
the following security issues:

Improper input validation in firmware for Intel(R) PROSet/Wireless Wi-Fi
may allow an unauthenticated user to potentially enable escalation of
privilege via local access (CVE-2021-0066 / SA-00539).

Improper input validation in firmware for some Intel(R) PROSet/Wireless
Wi-Fi may allow a privileged user to potentially enable information
disclosure via local access (CVE-2021-0072 / SA-00539).

Improper Validation of Specified Index, Position, or Offset in Input in
firmware for some Intel(R) PROSet/Wireless Wi-Fi may allow a privileged
user to potentially enable denial of service via local access
(CVE-2021-0076 / SA-00539).

Improper input validation in firmware for Intel(R) PROSet/Wireless Wi-Fi
may allow a privileged user to potentially enable escalation of privilege
via local access (CVE-2021-0161, CVE-2021-0168 / SA-00539).

Improper access control in firmware for Intel(R) PROSet/Wireless Wi-Fi may
allow an unauthenticated user to potentially enable escalation of privilege
via local access (CVE-2021-0164 / SA-00539).

Improper input validation in firmware for Intel(R) PROSet/Wireless Wi-Fi
may allow an unauthenticated user to potentially enable denial of service
via adjacent access (CVE-2021-0165 / SA-00539).

Exposure of Sensitive Information to an Unauthorized Actor in firmware for
some Intel(R) PROSet/Wireless Wi-Fi may allow a privileged user to potentially
enable escalation of privilege via local access (CVE-2021-0166 / SA-00539).

Exposure of Sensitive Information to an Unauthorized Actor in firmware for
some Intel(R) PROSet/Wireless Wi-Fi may allow an authenticated user to
potentially enable information disclosure via local access
(CVE-2021-0170 / SA-00539).

Improper input validation in firmware for some Intel(R) PROSet/Wireless Wi-Fi
may allow an unauthenticated user to potentially enable denial of service via
adjacent access (CVE-2021-0172 / SA-00539).

Improper Validation of Consistency within input in firmware for some Intel(R)
PROSet/Wireless Wi-Fi may allow a unauthenticated user to potentially enable
denial of service via adjacent access (CVE-2021-0173 / SA-00539).

Improper Use of Validation Framework in firmware for some Intel(R) PROSet/
Wireless Wi-Fi may allow a unauthenticated user to potentially enable denial
of service via adjacent access (CVE-2021-0174 / SA-00539).

Improper Validation of Specified Index, Position, or Offset in Input in
firmware for some Intel(R) PROSet/Wireless Wi-Fi may allow an unauthenticated
user to potentially enable denial of service via adjacent access
(CVE-2021-0175 / SA-00539).

Improper input validation in firmware for some Intel(R) PROSet/Wireless Wi-Fi
may allow a privileged user to potentially enable denial of service via local
access (CVE-2021-0176 / SA-00539).

Improper conditions check in firmware for some ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-firmware-nonfree, radeon-firmware' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-firmware", rpm:"iwlwifi-firmware~20220209~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nonfree", rpm:"kernel-firmware-nonfree~20220209~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radeon-firmware", rpm:"radeon-firmware~20220209~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ralink-firmware", rpm:"ralink-firmware~20220209~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rtlwifi-firmware", rpm:"rtlwifi-firmware~20220209~1.mga8.nonfree", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
