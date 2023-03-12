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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.264");
  script_cve_id("CVE-2015-3406", "CVE-2015-3407", "CVE-2015-3408", "CVE-2015-3409");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-16 19:48:00 +0000 (Mon, 16 Dec 2019)");

  script_name("Debian: Security Advisory (DLA-264)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-264");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-264");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libmodule-signature-perl' package(s) announced via the DLA-264 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"John Lightsey discovered multiple vulnerabilities in Module::Signature, a Perl module to manipulate CPAN SIGNATURE files. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-3406

Module::Signature could parse the unsigned portion of the SIGNATURE file as the signed portion due to incorrect handling of PGP signature boundaries.

CVE-2015-3407

Module::Signature incorrectly handled files that are not listed in the SIGNATURE file. This includes some files in the t/ directory that would execute when tests are run.

CVE-2015-3408

Module::Signature used two argument open() calls to read the files when generating checksums from the signed manifest. This allowed to embed arbitrary shell commands into the SIGNATURE file that would be executed during the signature verification process.

CVE-2015-3409

Module::Signature incorrectly handled module loading, allowing to load modules from relative paths in @INC. A remote attacker providing a malicious module could use this issue to execute arbitrary code during signature verification.

For the squeeze distribution, these issues have been fixed in version 0.63-1+squeeze2 of libmodule-signature-perl. Please note that the libtest-signature-perl package was also updated for compatibility with the CVE-2015-3407 fix.

We recommend that you upgrade your libmodule-signature-perl and libtest-signature-perl packages.");

  script_tag(name:"affected", value:"'libmodule-signature-perl' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmodule-signature-perl", ver:"0.63-1+squeeze2", rls:"DEB6"))) {
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
