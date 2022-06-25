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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0009");
  script_cve_id("CVE-2021-35515", "CVE-2021-35516", "CVE-2021-35517", "CVE-2021-36090");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-27 00:15:00 +0000 (Tue, 27 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2022-0009)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0009");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0009.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29254");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/07/13/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/07/13/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/07/13/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/07/13/4");
  script_xref(name:"URL", value:"https://commons.apache.org/proper/commons-compress/security-reports.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XVOH7P2WI6SSS2OORQJBS45T5SKKO7BV/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache-commons-compress, osgi-core' package(s) announced via the MGASA-2022-0009 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"When reading a specially crafted 7Z archive, the construction of the list
of codecs that decompress an entry can result in an infinite loop. This
could be used to mount a denial of service attack against services that
use Compress' sevenz package. (CVE-2021-35515)
When reading a specially crafted 7Z archive, Compress can be made to
allocate large amounts of memory that finally leads to an out of memory
error even for very small inputs. This could be used to mount a denial of
service attack against services that use Compress' sevenz package.
(CVE-2021-35516)
When reading a specially crafted TAR archive, Compress can be made to
allocate large amounts of memory that finally leads to an out of memory
error even for very small inputs. This could be used to mount a denial of
service attack against services that use Compress' tar package.
(CVE-2021-35517)
When reading a specially crafted ZIP archive, Compress can be made to
allocate large amounts of memory that finally leads to an out of memory
error even for very small inputs. This could be used to mount a denial of
service attack against services that use Compress' zip package.
(CVE-2021-36090)");

  script_tag(name:"affected", value:"'apache-commons-compress, osgi-core' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-compress", rpm:"apache-commons-compress~1.21~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-compress-javadoc", rpm:"apache-commons-compress-javadoc~1.21~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"osgi-core", rpm:"osgi-core~8.0.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"osgi-core-javadoc", rpm:"osgi-core-javadoc~8.0.0~1.mga8", rls:"MAGEIA8"))) {
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
