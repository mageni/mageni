# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.876634");
  script_version("2019-08-14T07:16:43+0000");
  script_cve_id("CVE-2019-3855", "CVE-2019-13115", "CVE-2019-3863", "CVE-2019-3856",
                "CVE-2019-3861", "CVE-2019-3857", "CVE-2019-3862", "CVE-2019-3858",
                "CVE-2019-3860", "CVE-2019-3859");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-08-14 07:16:43 +0000 (Wed, 14 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-05 02:17:35 +0000 (Mon, 05 Aug 2019)");
  script_name("Fedora Update for libssh2 FEDORA-2019-5885663621");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC29");

  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/M7IF3LNHOA75O4WZWIHJLIRMA5LJUED3");

  script_tag(name:"summary", value:"The remote host is missing an update for the
  'libssh2' package(s) announced via the FEDORA-2019-5885663621 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is
  present on the target host.");

  script_tag(name:"insight", value:"libssh2 is a library implementing the SSH2
  protocol as defined by Internet Drafts: SECSH-TRANS(22), SECSH-USERAUTH(25),
  SECSH-CONNECTION(23), SECSH-ARCH(20), SECSH-FILEXFER(06)*, SECSH-DHGEX(04),
  and SECSH-NUMBERS(10).");

  script_tag(name:"affected", value:"'libssh2' package(s) on Fedora 29.");

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

if(release == "FC29") {

  if(!isnull(res = isrpmvuln(pkg:"libssh2", rpm:"libssh2~1.9.0~1.fc29", rls:"FC29"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
