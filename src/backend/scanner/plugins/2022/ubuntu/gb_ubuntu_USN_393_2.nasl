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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.393.2");
  script_cve_id("CVE-2006-6169", "CVE-2006-6235");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-393-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU6\.10");

  script_xref(name:"Advisory-ID", value:"USN-393-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-393-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg2' package(s) announced via the USN-393-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-389-1 and USN-393-1 fixed vulnerabilities in gnupg. This update
provides the corresponding updates for gnupg2.

Original advisory details:

 A buffer overflow was discovered in GnuPG. By tricking a user into
 running gpg interactively on a specially crafted message, an attacker
 could execute arbitrary code with the user's privileges. This
 vulnerability is not exposed when running gpg in batch mode.
 (CVE-2006-6169)

 Tavis Ormandy discovered that gnupg was incorrectly using the stack.
 If a user were tricked into processing a specially crafted message, an
 attacker could execute arbitrary code with the user's privileges.
 (CVE-2006-6235)");

  script_tag(name:"affected", value:"'gnupg2' package(s) on Ubuntu 6.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU6.10") {

  if(!isnull(res = isdpkgvuln(pkg:"gnupg2", ver:"1.9.21-0ubuntu5.2", rls:"UBUNTU6.10"))) {
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
