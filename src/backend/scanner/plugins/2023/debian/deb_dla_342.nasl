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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.342");
  script_cve_id("CVE-2015-3282", "CVE-2015-3283", "CVE-2015-3285", "CVE-2015-6587", "CVE-2015-7762", "CVE-2015-7763");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DLA-342)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-342");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-342");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openafs' package(s) announced via the DLA-342 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found and solved in the distributed file system OpenAFS:

CVE-2015-3282

vos leaked stack data clear on the wire when updating vldb entries.

CVE-2015-3283

OpenAFS allowed remote attackers to spoof bos commands via unspecified vectors.

CVE-2015-3285

pioctl wrongly used the pointer related to the RPC, allowing local users to cause a denial of service (memory corruption and kernel panic) via a crafted OSD FS command.

CVE-2015-6587

vlserver allowed remote authenticated users to cause a denial of service (out-of-bounds read and crash) via a crafted regular expression in a VL_ListAttributesN2 RPC.

CVE-2015-7762 and CVE-2015-7763 ('Tattletale') John Stumpo found that Rx ACK packets leaked plaintext of packets previously processed.

For Debian 6 Squeeze, these problems have been fixed in openafs version 1.4.12.1+dfsg-4+squeeze4.

We recommend that you upgrade your OpenAFS packages.");

  script_tag(name:"affected", value:"'openafs' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libopenafs-dev", ver:"1.4.12.1+dfsg-4+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpam-openafs-kaserver", ver:"1.4.12.1+dfsg-4+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-client", ver:"1.4.12.1+dfsg-4+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-dbg", ver:"1.4.12.1+dfsg-4+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-dbserver", ver:"1.4.12.1+dfsg-4+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-doc", ver:"1.4.12.1+dfsg-4+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-fileserver", ver:"1.4.12.1+dfsg-4+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-kpasswd", ver:"1.4.12.1+dfsg-4+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-krb5", ver:"1.4.12.1+dfsg-4+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-modules-dkms", ver:"1.4.12.1+dfsg-4+squeeze4", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openafs-modules-source", ver:"1.4.12.1+dfsg-4+squeeze4", rls:"DEB6"))) {
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
