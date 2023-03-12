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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.379");
  script_cve_id("CVE-2015-5252", "CVE-2015-5296", "CVE-2015-5299");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 20:26:00 +0000 (Mon, 29 Aug 2022)");

  script_name("Debian: Security Advisory (DLA-379)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-379");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-379");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'samba' package(s) announced via the DLA-379 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were found in Samba, a SMB/CIFS implementation that provides a file, print, and login server.

CVE-2015-5252

Jan Yenya Kasprzak and the Computer Systems Unit team at Faculty of Informatics, Masaryk University, reported that samba wrongly verified symlinks, making it possible to access resources outside the shared path, under certain circumstances.

CVE-2015-5296

Stefan Metzmacher of SerNet and the Samba Team discovered that samba did not ensure that signing was negotiated when a client established an encrypted connection against a samba server.

CVE-2015-5299

Samba was vulnerable to a missing access control check in the VFS shadow_copy2 module, that could allow unauthorized users to access snapshots.

For Debian 6 Squeeze, this issue has been fixed in samba version 2:3.5.6~dfsg-3squeeze13. We recommend you to upgrade your samba packages.");

  script_tag(name:"affected", value:"'samba' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpam-smbpass", ver:"2:3.5.6~dfsg-3squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"2:3.5.6~dfsg-3squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsmbclient", ver:"2:3.5.6~dfsg-3squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwbclient0", ver:"2:3.5.6~dfsg-3squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:3.5.6~dfsg-3squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-common", ver:"2:3.5.6~dfsg-3squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-dbg", ver:"2:3.5.6~dfsg-3squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-doc-pdf", ver:"2:3.5.6~dfsg-3squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-doc", ver:"2:3.5.6~dfsg-3squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba-tools", ver:"2:3.5.6~dfsg-3squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:3.5.6~dfsg-3squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"smbclient", ver:"2:3.5.6~dfsg-3squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"swat", ver:"2:3.5.6~dfsg-3squeeze13", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"winbind", ver:"2:3.5.6~dfsg-3squeeze13", rls:"DEB6"))) {
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
