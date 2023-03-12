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
  script_oid("1.3.6.1.4.1.25623.1.0.893315");
  script_cve_id("CVE-2019-13590", "CVE-2021-23159", "CVE-2021-23172", "CVE-2021-23210", "CVE-2021-33844", "CVE-2021-3643", "CVE-2021-40426", "CVE-2022-31650", "CVE-2022-31651");
  script_tag(name:"creation_date", value:"2023-02-11 02:00:13 +0000 (Sat, 11 Feb 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-10 17:00:00 +0000 (Tue, 10 May 2022)");

  script_name("Debian: Security Advisory (DLA-3315)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3315");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3315");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/sox");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sox' package(s) announced via the DLA-3315 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes multiple file format validation vulnerabilities that could result in memory access violations such as buffer overflows and floating point exceptions. It also fixes a regression in hcom parsing introduced when fixing CVE-2017-11358.

CVE-2019-13590

In sox-fmt.h (startread function), there is an integer overflow on the result of integer addition (wraparound to 0) fed into the lsx_calloc macro that wraps malloc. When a NULL pointer is returned, it is used without a prior check that it is a valid pointer, leading to a NULL pointer dereference on lsx_readbuf in formats_i.c.

CVE-2021-3643

The lsx_adpcm_init function within libsox leads to a global-buffer-overflow. This flaw allows an attacker to input a malicious file, leading to the disclosure of sensitive information.

CVE-2021-23159

A vulnerability was found in SoX, where a heap-buffer-overflow occurs in function lsx_read_w_buf() in formats_i.c file. The vulnerability is exploitable with a crafted file, that could cause an application to crash.

CVE-2021-23172

A vulnerability was found in SoX, where a heap-buffer-overflow occurs in function startread() in hcom.c file. The vulnerability is exploitable with a crafted hcomn file, that could cause an application to crash.

CVE-2021-23210

A floating point exception (divide-by-zero) issue was discovered in SoX in function read_samples() of voc.c file. An attacker with a crafted file, could cause an application to crash.

CVE-2021-33844

A floating point exception (divide-by-zero) issue was discovered in SoX in function startread() of wav.c file. An attacker with a crafted wav file, could cause an application to crash.

CVE-2021-40426

A heap-based buffer overflow vulnerability exists in the sphere.c start_read() functionality of Sound Exchange libsox. A specially-crafted file can lead to a heap buffer overflow. An attacker can provide a malicious file to trigger this vulnerability.

CVE-2022-31650

There is a floating-point exception in lsx_aiffstartwrite in aiff.c.

CVE-2022-31651

There is an assertion failure in rate_init in rate.c.

For Debian 10 buster, these problems have been fixed in version 14.4.2+git20190427-1+deb10u1.

We recommend that you upgrade your sox packages.

For the detailed security status of sox please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'sox' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libsox-dev", ver:"14.4.2+git20190427-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-all", ver:"14.4.2+git20190427-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-alsa", ver:"14.4.2+git20190427-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-ao", ver:"14.4.2+git20190427-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-base", ver:"14.4.2+git20190427-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-mp3", ver:"14.4.2+git20190427-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-oss", ver:"14.4.2+git20190427-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox-fmt-pulse", ver:"14.4.2+git20190427-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsox3", ver:"14.4.2+git20190427-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sox", ver:"14.4.2+git20190427-1+deb10u1", rls:"DEB10"))) {
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
