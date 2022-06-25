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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0299");
  script_cve_id("CVE-2013-4351", "CVE-2013-4402");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-01-04 04:48:00 +0000 (Sat, 04 Jan 2014)");

  script_name("Mageia: Security Advisory (MGASA-2013-0299)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0299");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0299.html");
  script_xref(name:"URL", value:"http://lists.gnu.org/archive/html/info-gnu/2013-10/msg00002.html");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2013-09/msg00058.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11306");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg2, gnupg2' package(s) announced via the MGASA-2013-0299 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated gnupg2 package fixes security vulnerabilities:

RFC 4880 permits OpenPGP keyholders to mark their primary keys and subkeys
with a 'key flags' packet that indicates the capabilities of the key. These
are represented as a set of binary flags, including things like 'This key may
be used to encrypt communications.' If a key or subkey has this 'key flags'
subpacket attached with all bits cleared (off), GnuPG currently treats the key
as having all bits set (on). While keys with this sort of marker are very rare
in the wild, GnuPG's misinterpretation of this subpacket could lead to a
breach of confidentiality or a mistaken identity verification (CVE-2013-4351).

Special crafted input data may be used to cause a denial of service against
GPG. GPG can be forced to recursively parse certain parts of OpenPGP messages
ad infinitum (CVE-2013-4402).");

  script_tag(name:"affected", value:"'gnupg2, gnupg2' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"gnupg2", rpm:"gnupg2~2.0.18~1.4.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"gnupg2", rpm:"gnupg2~2.0.19~3.2.mga3", rls:"MAGEIA3"))) {
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
