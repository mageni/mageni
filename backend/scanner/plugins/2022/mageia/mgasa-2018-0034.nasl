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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0034");
  script_cve_id("CVE-2014-8501", "CVE-2014-9939", "CVE-2016-2226", "CVE-2016-4487", "CVE-2016-4488", "CVE-2016-4489", "CVE-2016-4490", "CVE-2016-4491", "CVE-2016-4492", "CVE-2016-4493", "CVE-2016-6131");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-22 19:12:00 +0000 (Wed, 22 Mar 2017)");

  script_name("Mageia: Security Advisory (MGASA-2018-0034)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0034");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0034.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21376");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/usn/usn-3367-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdb' package(s) announced via the MGASA-2018-0034 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hanno Bock discovered that gdb incorrectly handled certain malformed AOUT
headers in PE executables. If a user or automated system were tricked into
processing a specially crafted binary, a remote attacker could use this
issue to cause gdb to crash, resulting in a denial of service, or possibly
execute arbitrary code (CVE-2014-8501).

It was discovered that gdb incorrectly handled printing bad bytes in Intel
Hex objects. If a user or automated system were tricked into processing a
specially crafted binary, a remote attacker could use this issue to cause
gdb to crash, resulting in a denial of service (CVE-2014-9939).

It was discovered that gdb incorrectly handled certain string operations.
If a user or automated system were tricked into processing a specially
crafted binary, a remote attacker could use this issue to cause gdb to
crash, resulting in a denial of service, or possibly execute arbitrary
code (CVE-2016-2226).

It was discovered that gdb incorrectly handled parsing certain binaries.
If a user or automated system were tricked into processing a specially
crafted binary, a remote attacker could use this issue to cause gdb to
crash, resulting in a denial of service (CVE-2016-4487, CVE-2016-4488,
CVE-2016-4489, CVE-2016-4490, CVE-2016-4491, CVE-2016-4492, CVE-2016-4493,
CVE-2016-6131).");

  script_tag(name:"affected", value:"'gdb' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"gdb", rpm:"gdb~7.8.1~7.1.mga5", rls:"MAGEIA5"))) {
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
