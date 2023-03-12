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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.438");
  script_cve_id("CVE-2015-8790", "CVE-2015-8791");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:14:00 +0000 (Sat, 03 Dec 2016)");

  script_name("Debian: Security Advisory (DLA-438)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-438");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-438");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libebml' package(s) announced via the DLA-438 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security-related issues were fixed in libebml, a library for accessing the EBML format:

CVE-2015-8790

The EbmlUnicodeString::UpdateFromUTF8 function in libEBML before 1.3.3 allows context-dependent attackers to obtain sensitive information from process heap memory via a crafted UTF-8 string, which triggers an invalid memory access.

CVE-2015-8791

The EbmlElement::ReadCodedSizeValue function in libEBML before 1.3.3 allows context-dependent attackers to obtain sensitive information from process heap memory via a crafted length value in an EBML id, which triggers an invalid memory access.

For Debian 6 squeeze, these issues have been fixed in libebml version 0.7.7-3.1+deb6u1. We recommend you to upgrade your libebml packages.");

  script_tag(name:"affected", value:"'libebml' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libebml-dev", ver:"0.7.7-3.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libebml0", ver:"0.7.7-3.1+deb6u1", rls:"DEB6"))) {
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
