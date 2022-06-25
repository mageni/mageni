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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0441");
  script_cve_id("CVE-2021-3634");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-09 01:02:00 +0000 (Thu, 09 Sep 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0441)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0441");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0441.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29419");
  script_xref(name:"URL", value:"https://www.libssh.org/security/advisories/CVE-2021-3634.txt");
  script_xref(name:"URL", value:"https://www.libssh.org/2021/08/26/libssh-0-9-6-security-release/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5053-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4965");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh' package(s) announced via the MGASA-2021-0441 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw has been found in libssh in versions prior to 0.9.6. The SSH
protocol keeps track of two shared secrets during the lifetime of the
session. One of them is called secret_hash and the other session_id.
Initially, both of them are the same, but after key re-exchange, previous
session_id is kept and used as an input to new secret_hash. Historically,
both of these buffers had shared length variable, which worked as long as
these buffers were same. But the key re-exchange operation can also change
the key exchange method, which can be based on hash of different size,
eventually creating 'secret_hash' of different size than the session_id
has. This becomes an issue when the session_id memory is zeroed or when it
is used again during second key re-exchange. (CVE-2021-3634)");

  script_tag(name:"affected", value:"'libssh' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ssh-devel", rpm:"lib64ssh-devel~0.9.6~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ssh4", rpm:"lib64ssh4~0.9.6~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh", rpm:"libssh~0.9.6~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh-devel", rpm:"libssh-devel~0.9.6~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh4", rpm:"libssh4~0.9.6~1.mga8", rls:"MAGEIA8"))) {
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
