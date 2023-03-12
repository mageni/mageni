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
  script_oid("1.3.6.1.4.1.25623.1.0.893340");
  script_cve_id("CVE-2020-12278", "CVE-2020-12279", "CVE-2023-22742");
  script_tag(name:"creation_date", value:"2023-02-24 02:00:14 +0000 (Fri, 24 Feb 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-04 16:31:00 +0000 (Mon, 04 May 2020)");

  script_name("Debian: Security Advisory (DLA-3340)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3340");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3340");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libgit2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libgit2' package(s) announced via the DLA-3340 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability have been found in libgit2, a cross-platform, linkable library implementation of Git, which may result in remote code execution when cloning a repository on a NTFS-like filesystem or man-in-the-middle attacks due to improper verification of cryptographic Signature.

CVE-2020-12278

An issue was discovered in libgit2 before 0.28.4 and 0.9x before 0.99.0. path.c mishandles equivalent filenames that exist because of NTFS Alternate Data Streams. This may allow remote code execution when cloning a repository.

CVE-2020-12279

An issue was discovered in libgit2 before 0.28.4 and 0.9x before 0.99.0. checkout.c mishandles equivalent filenames that exist because of NTFS short names. This may allow remote code execution when cloning a repository

CVE-2023-22742

libgit2 is a cross-platform, linkable library implementation of Git. When using an SSH remote with the optional libssh2 backend, libgit2 does not perform certificate checking by default. Prior versions of libgit2 require the caller to set the `certificate_check` field of libgit2's `git_remote_callbacks` structure - if a certificate check callback is not set, libgit2 does not perform any certificate checking. This means that by default - without configuring a certificate check callback, clients will not perform validation on the server SSH keys and may be subject to a man-in-the-middle attack.

For Debian 10 buster, these problems have been fixed in version 0.27.7+dfsg.1-0.2+deb10u1.

We recommend that you upgrade your libgit2 packages.

For the detailed security status of libgit2 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libgit2' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libgit2-27", ver:"0.27.7+dfsg.1-0.2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgit2-dev", ver:"0.27.7+dfsg.1-0.2+deb10u1", rls:"DEB10"))) {
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
