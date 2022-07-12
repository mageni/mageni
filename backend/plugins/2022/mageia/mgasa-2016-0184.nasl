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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0184");
  script_cve_id("CVE-2015-8872", "CVE-2016-4804");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-30 18:15:00 +0000 (Sat, 30 May 2020)");

  script_name("Mageia: Security Advisory (MGASA-2016-0184)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0184");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0184.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18462");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/05/14/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dosfstools' package(s) announced via the MGASA-2016-0184 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated dosfstools package fixes security vulnerabilities:

In dosfstools before 4.0, if the third to last entry was written on a FAT12
filesystem with an odd number of clusters, the second to last entry would be
corrupted. This corruption may also lead to invalid memory accesses when the
corrupted entry becomes out of bounds and is used later (CVE-2015-8872).

In dosfstools before 4.0, the variable used for storing the FAT size (in bytes)
was an unsigned int. Since the size in sectors read from the BPB was not
sufficiently checked, this could end up being zero after multiplying it with
the sector size while some offsets still stayed excessive. Ultimately it would
cause segfaults when accessing FAT entries for which no memory was allocated
(CVE-2016-4804).");

  script_tag(name:"affected", value:"'dosfstools' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"dosfstools", rpm:"dosfstools~3.0.27~1.1.mga5", rls:"MAGEIA5"))) {
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
