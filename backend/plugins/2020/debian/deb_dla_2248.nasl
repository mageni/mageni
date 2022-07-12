# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892248");
  script_version("2020-06-14T03:00:22+0000");
  script_cve_id("CVE-2020-0543", "CVE-2020-0548", "CVE-2020-0549");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-06-15 12:06:35 +0000 (Mon, 15 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-14 03:00:22 +0000 (Sun, 14 Jun 2020)");
  script_name("Debian LTS: Security Advisory for intel-microcode (DLA-2248-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/06/msg00019.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2248-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'intel-microcode'
  package(s) announced via the DLA-2248-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following CVE(s) were reported against src:intel-microcode.

CVE-2020-0543

A new domain bypass transient execution attack known as Special
Register Buffer Data Sampling (SRBDS) has been found. This flaw
allows data values from special internal registers to be leaked
by an attacker able to execute code on any core of the CPU. An
unprivileged, local attacker can use this flaw to infer values
returned by affected instructions known to be commonly used
during cryptographic operations that rely on uniqueness, secrecy,
or both.

CVE-2020-0548

A flaw was found in Intel processors where a local attacker is
able to gain information about registers used for vector
calculations by observing register states from other processes
running on the system. This results in a race condition where
store buffers, which were not cleared, could be read by another
process or a CPU sibling. The highest threat from this
vulnerability is data confidentiality where an attacker could
read arbitrary data as it passes through the processor.

CVE-2020-0549

A microarchitectural timing flaw was found on some Intel
processors. A corner case exists where data in-flight during the
eviction process can end up in the 'fill buffers' and not properly
cleared by the MDS mitigations. The fill buffer contents (which
were expected to be blank) can be inferred using MDS or TAA style
attack methods to allow a local attacker to infer fill buffer
values.");

  script_tag(name:"affected", value:"'intel-microcode' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.20200609.2~deb8u1.

We recommend that you upgrade your intel-microcode packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20200609.2~deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
