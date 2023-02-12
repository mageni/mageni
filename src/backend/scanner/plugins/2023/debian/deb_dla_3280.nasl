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
  script_oid("1.3.6.1.4.1.25623.1.0.893280");
  script_version("2023-01-26T10:11:56+0000");
  script_cve_id("CVE-2020-21596", "CVE-2020-21597", "CVE-2020-21598", "CVE-2022-43235", "CVE-2022-43236", "CVE-2022-43237", "CVE-2022-43238", "CVE-2022-43239", "CVE-2022-43240", "CVE-2022-43241", "CVE-2022-43242", "CVE-2022-43243", "CVE-2022-43244", "CVE-2022-43245", "CVE-2022-43248", "CVE-2022-43249", "CVE-2022-43250", "CVE-2022-43252", "CVE-2022-43253", "CVE-2022-47655");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-01-26 10:11:56 +0000 (Thu, 26 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-27 20:28:00 +0000 (Mon, 27 Sep 2021)");
  script_tag(name:"creation_date", value:"2023-01-25 02:00:16 +0000 (Wed, 25 Jan 2023)");
  script_name("Debian LTS: Security Advisory for libde265 (DLA-3280-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00020.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3280-1");
  script_xref(name:"Advisory-ID", value:"DLA-3280-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1025816");
  script_xref(name:"URL", value:"https://bugs.debian.org/1027179");
  script_xref(name:"URL", value:"https://bugs.debian.org/1029357");
  script_xref(name:"URL", value:"https://bugs.debian.org/1029397");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libde265'
  package(s) announced via the DLA-3280-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues were found in libde265, an open source implementation
of the H.265 video codec, which may result in denial of service or have
unspecified other impact.

CVE-2020-21596

libde265 v1.0.4 contains a global buffer overflow in the
decode_CABAC_bit function, which can be exploited via a crafted a
file.

CVE-2020-21597

libde265 v1.0.4 contains a heap buffer overflow in the mc_chroma
function, which can be exploited via a crafted a file.

CVE-2020-21598

libde265 v1.0.4 contains a heap buffer overflow in the
ff_hevc_put_unweighted_pred_8_sse function, which can be exploited
via a crafted a file.

CVE-2022-43235

Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow
vulnerability via ff_hevc_put_hevc_epel_pixels_8_sse in
sse-motion.cc. This vulnerability allows attackers to cause a Denial
of Service (DoS) via a crafted video file.

CVE-2022-43236

Libde265 v1.0.8 was discovered to contain a stack-buffer-overflow
vulnerability via put_qpel_fallback<unsigned short> in
fallback-motion.cc. This vulnerability allows attackers to cause a
Denial of Service (DoS) via a crafted video file.

CVE-2022-43237

Libde265 v1.0.8 was discovered to contain a stack-buffer-overflow
vulnerability via void put_epel_hv_fallback<unsigned short> in
fallback-motion.cc. This vulnerability allows attackers to cause a
Denial of Service (DoS) via a crafted video file.

CVE-2022-43238

Libde265 v1.0.8 was discovered to contain an unknown crash via
ff_hevc_put_hevc_qpel_h_3_v_3_sse in sse-motion.cc. This
vulnerability allows attackers to cause a Denial of Service (DoS)
via a crafted video file.

CVE-2022-43239

Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow
vulnerability via mc_chroma<unsigned short> in motion.cc. This
vulnerability allows attackers to cause a Denial of Service (DoS)
via a crafted video file.

CVE-2022-43240

Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow
vulnerability via ff_hevc_put_hevc_qpel_h_2_v_1_sse in
sse-motion.cc. This vulnerability allows attackers to cause a Denial
of Service (DoS) via a crafted video file.

CVE-2022-43241

Libde265 v1.0.8 was discovered to contain an unknown crash via
ff_hevc_put_hevc_qpel_v_3_8_sse in sse-motion.cc. This vulnerability
allows attackers to cause a Denial of Service (DoS) via a crafted
video file.

CVE-2022-43242

Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow
vulnerability via mc_luma<unsigned char> in motion.cc. This
vulnerability allows attackers to cause a Denial of Service (DoS)
via a crafted video file.

CVE-2022-43243

Libde265 v1.0.8 was discovered to contain a heap-buffer-overflow
vulnerability via ff_h ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'libde265' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
1.0.3-1+deb10u2.

We recommend that you upgrade your libde265 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libde265-0", ver:"1.0.3-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libde265-dev", ver:"1.0.3-1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libde265-examples", ver:"1.0.3-1+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
