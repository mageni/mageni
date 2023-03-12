# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.317");
  script_cve_id("CVE-2014-9638", "CVE-2014-9639", "CVE-2014-9640", "CVE-2015-6749");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DLA-317)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-317");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-317");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vorbis-tools' package(s) announced via the DLA-317 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various issues have been fixed in Debian LTS (squeeze) for package vorbis-tools.

CVE-2014-9638

A crafted WAV file with number of channels set to 0 will cause oggenc to crash due to a division by zero issue. This issue has been fixed upstream by providing a fix for CVE-2014-9639. Reported upstream by zuBux.

CVE-2014-9639

An integer overflow issue was discovered in oggenc, related to the number of channels in the input WAV file. The issue triggers an out-of-bounds memory access which causes oggenc to crash here (audio.c). Reported upstream by zuBux.

The upstream fix for this has been backported to vorbis-tools in Debian LTS (squeeze).

CVE-2014-9640

Fix for a crash on closing raw input (dd if=/dev/zero bs=1 count=1 <pipe> oggenc -r - -o out.ogg). Reported upstream by hanno.

The upstream fix for this has been backported to vorbis-tools in Debian LTS (squeeze).

CVE-2015-6749

Buffer overflow in the aiff_open function in oggenc/audio.c in vorbis-tools 1.4.0 and earlier allowed remote attackers to cause a denial of service (crash) via a crafted AIFF file. Reported upstream by pengsu.

The upstream fix for this has been backported to vorbis-tools in Debian LTS (squeeze).");

  script_tag(name:"affected", value:"'vorbis-tools' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"vorbis-tools-dbg", ver:"1.4.0-1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vorbis-tools", ver:"1.4.0-1+deb6u1", rls:"DEB6"))) {
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
