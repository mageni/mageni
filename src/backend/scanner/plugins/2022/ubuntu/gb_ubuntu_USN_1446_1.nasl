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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2012.1446.1");
  script_cve_id("CVE-2011-4086", "CVE-2012-1090", "CVE-2012-1097", "CVE-2012-1146", "CVE-2012-1179", "CVE-2012-4398");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 20:14:00 +0000 (Mon, 27 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-1446-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.10");

  script_xref(name:"Advisory-ID", value:"USN-1446-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1446-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4' package(s) announced via the USN-1446-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the Linux's kernels ext4 file system when mounted with
a journal. A local, unprivileged user could exploit this flaw to cause a
denial of service. (CVE-2011-4086)

A flaw was discovered in the Linux kernel's cifs file system. An
unprivileged local user could exploit this flaw to crash the system leading
to a denial of service. (CVE-2012-1090)

H. Peter Anvin reported a flaw in the Linux kernel that could crash the
system. A local user could exploit this flaw to crash the system.
(CVE-2012-1097)

A flaw was discovered in the Linux kernel's cgroups subset. A local
attacker could use this flaw to crash the system. (CVE-2012-1146)

A flaw was found in the Linux kernel's handling of paged memory. A local
unprivileged user, or a privileged user within a KVM guest, could exploit
this flaw to crash the system. (CVE-2012-1179)

Tetsuo Handa reported a flaw in the OOM (out of memory) killer of the Linux
kernel. A local unprivileged user can exploit this flaw to cause system
unstability and denial of services. (CVE-2012-4398)");

  script_tag(name:"affected", value:"'linux-ti-omap4' package(s) on Ubuntu 11.10.");

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

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.0.0-1209-omap4", ver:"3.0.0-1209.21", rls:"UBUNTU11.10"))) {
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
