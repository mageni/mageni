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
  script_oid("1.3.6.1.4.1.25623.1.0.893305");
  script_version("2023-02-02T10:09:00+0000");
  script_cve_id("CVE-2018-16981", "CVE-2019-13217", "CVE-2019-13218", "CVE-2019-13219", "CVE-2019-13220", "CVE-2019-13221", "CVE-2019-13222", "CVE-2019-13223", "CVE-2021-28021", "CVE-2021-37789", "CVE-2021-42715", "CVE-2022-28041", "CVE-2022-28042");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-02-02 10:09:00 +0000 (Thu, 02 Feb 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2023-02-01 02:00:18 +0000 (Wed, 01 Feb 2023)");
  script_name("Debian LTS: Security Advisory for libstb (DLA-3305-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00045.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3305-1");
  script_xref(name:"Advisory-ID", value:"DLA-3305-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/934966");
  script_xref(name:"URL", value:"https://bugs.debian.org/1014530");
  script_xref(name:"URL", value:"https://bugs.debian.org/1023693");
  script_xref(name:"URL", value:"https://bugs.debian.org/1014531");
  script_xref(name:"URL", value:"https://bugs.debian.org/1014532");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libstb'
  package(s) announced via the DLA-3305-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been fixed in the libstb library.

CVE-2018-16981

Heap-based buffer overflow in stbi__out_gif_code().

CVE-2019-13217

Heap buffer overflow in the Vorbis start_decoder().

CVE-2019-13218

Division by zero in the Vorbis predict_point().

CVE-2019-13219

NULL pointer dereference in the Vorbis get_window().

CVE-2019-13220

Uninitialized stack variables in the Vorbis start_decoder().

CVE-2019-13221

Buffer overflow in the Vorbis compute_codewords().

CVE-2019-13222

Out-of-bounds read of a global buffer in the Vorbis draw_line().

CVE-2019-13223

Reachable assertion in the Vorbis lookup1_values().

CVE-2021-28021

Buffer overflow in stbi__extend_receive().

CVE-2021-37789

Heap-based buffer overflow in stbi__jpeg_load().

CVE-2021-42715

The HDR loader parsed truncated end-of-file RLE scanlines as an
infinite sequence of zero-length runs.

CVE-2022-28041

Integer overflow in stbi__jpeg_decode_block_prog_dc().

CVE-2022-28042

Heap-based use-after-free in stbi__jpeg_huff_decode().");

  script_tag(name:"affected", value:"'libstb' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
0.0~git20180212.15.e6afb9c-1+deb10u1.

We recommend that you upgrade your libstb packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libstb-dev", ver:"0.0~git20180212.15.e6afb9c-1+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libstb0", ver:"0.0~git20180212.15.e6afb9c-1+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
