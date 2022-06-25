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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0425");
  script_cve_id("CVE-2016-4330", "CVE-2016-4331", "CVE-2016-4332", "CVE-2016-4333");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Mageia: Security Advisory (MGASA-2016-0425)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0425");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0425.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19874");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3727");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hdf5' package(s) announced via the MGASA-2016-0425 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the HDF5 1.8.16 library's failure to check if the number of
dimensions for an array read from the file is within the bounds of the
space allocated for it, a heap-based buffer overflow will occur,
potentially leading to arbitrary code execution (CVE-2016-4330).

When decoding data out of a dataset encoded with the H5Z_NBIT decoding,
the HDF5 1.8.16 library will fail to ensure that the precision is within
the bounds of the size leading to arbitrary code execution
(CVE-2016-4331).

The library's failure to check if certain message types support a
particular flag, the HDF5 1.8.16 library will cast the structure to an
alternative structure and then assign to fields that aren't supported by
the message type and the library will write outside the bounds of the
heap buffer. This can lead to code execution under the context of the
library (CVE-2016-4332).

The HDF5 1.8.16 library allocating space for the array using a value
from the file has an impact within the loop for initializing said array
allowing a value within the file to modify the loop's terminator. Due to
this, an aggressor can cause the loop's index to point outside the
bounds of the array when initializing it (CVE-2016-4333).");

  script_tag(name:"affected", value:"'hdf5' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"hdf5", rpm:"hdf5~1.8.13~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64hdf5-devel", rpm:"lib64hdf5-devel~1.8.13~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64hdf5_8", rpm:"lib64hdf5_8~1.8.13~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64hdf5_hl8", rpm:"lib64hdf5_hl8~1.8.13~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5-devel", rpm:"libhdf5-devel~1.8.13~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_8", rpm:"libhdf5_8~1.8.13~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdf5_hl8", rpm:"libhdf5_hl8~1.8.13~4.1.mga5", rls:"MAGEIA5"))) {
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
