# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892769");
  script_version("2021-10-01T08:01:29+0000");
  script_cve_id("CVE-2021-39139", "CVE-2021-39140", "CVE-2021-39141", "CVE-2021-39144", "CVE-2021-39145", "CVE-2021-39146", "CVE-2021-39147", "CVE-2021-39148", "CVE-2021-39149", "CVE-2021-39150", "CVE-2021-39151", "CVE-2021-39152", "CVE-2021-39153", "CVE-2021-39154");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-01 10:33:46 +0000 (Fri, 01 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-26 20:43:00 +0000 (Thu, 26 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-10-01 01:00:18 +0000 (Fri, 01 Oct 2021)");
  script_name("Debian LTS: Security Advisory for libxstream-java (DLA-2769-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/09/msg00017.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2769-1");
  script_xref(name:"Advisory-ID", value:"DLA-2769-1");
  script_xref(name:"URL", value:"https://x-stream.github.io/security.html#framework");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxstream-java'
  package(s) announced via the DLA-2769-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been discovered in XStream, a Java
library to serialize objects to XML and back again.

These vulnerabilities may allow a remote attacker to load and execute arbitrary
code from a remote host only by manipulating the processed input stream.

XStream itself sets up a whitelist by default now, i.e. it blocks all classes
except those types it has explicit converters for. It used to have a blacklist
by default, i.e. it tried to block all currently known critical classes of the
Java runtime. Main reason for the blacklist were compatibility, it allowed to
use newer versions of XStream as drop-in replacement. However, this approach
has failed. A growing list of security reports has proven, that a blacklist is
inherently unsafe, apart from the fact that types of 3rd libraries were not
even considered. A blacklist scenario should be avoided in general, because it
provides a false sense of security.

See also [link moved to references]");

  script_tag(name:"affected", value:"'libxstream-java' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1.4.11.1-1+deb9u4.

We recommend that you upgrade your libxstream-java packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libxstream-java", ver:"1.4.11.1-1+deb9u4", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
