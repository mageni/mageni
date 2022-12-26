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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0447");
  script_cve_id("CVE-2022-39316", "CVE-2022-39317", "CVE-2022-39318", "CVE-2022-39319", "CVE-2022-39320", "CVE-2022-39347");
  script_tag(name:"creation_date", value:"2022-12-07 04:12:01 +0000 (Wed, 07 Dec 2022)");
  script_version("2022-12-07T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-12-07 10:11:17 +0000 (Wed, 07 Dec 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-29 19:51:00 +0000 (Tue, 29 Nov 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0447)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0447");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0447.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31173");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5734-1");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-5w4j-mrrh-jjrm");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-99cm-4gw7-c8jh");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-387j-8j96-7q35");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-mvxm-wfj2-5fvh");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-qfq2-82qr-7f4j");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-c5xq-8v35-pffg");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the MGASA-2022-0447 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In affected versions there is an out of bound read in ZGFX decoder
component of FreeRDP. A malicious server can trick a FreeRDP based client
to read out of bound data and try to decode it likely resulting in a
crash. (CVE-2022-39316)

Affected versions of FreeRDP are missing a range check for input offset
index in ZGFX decoder. A malicious server can trick a FreeRDP based client
to read out of bound data and try to decode it. (CVE-2022-39317)

Affected versions of FreeRDP are missing input validation in 'urbdrc'
channel. A malicious server can trick a FreeRDP based client to crash with
division by zero. (CVE-2022-39318)

Affected versions of FreeRDP are missing input length validation in the
'urbdrc' channel. A malicious server can trick a FreeRDP based client to
read out of bound data and send it back to the server. (CVE-2022-39319)

Affected versions of FreeRDP may attempt integer addition on too narrow
types leads to allocation of a buffer too small holding the data written.
A malicious server can trick a FreeRDP based client to read out of bound
data and send it back to the server. (CVE-2022-39320)

Affected versions of FreeRDP are missing path canonicalization and base
path check for `drive` channel. A malicious server can trick a FreeRDP
based client to read files outside the shared directory. (CVE-2022-39347)");

  script_tag(name:"affected", value:"'freerdp' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.2.0~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp-devel", rpm:"lib64freerdp-devel~2.2.0~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp2", rpm:"lib64freerdp2~2.2.0~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp-devel", rpm:"libfreerdp-devel~2.2.0~1.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2", rpm:"libfreerdp2~2.2.0~1.4.mga8", rls:"MAGEIA8"))) {
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
