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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.680");
  script_cve_id("CVE-2016-7543");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Debian: Security Advisory (DLA-680)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-680");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-680-2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bash' package(s) announced via the DLA-680 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a correction of DLA 680-1 that mentioned that bash 4.2+dfsg-0.1+deb7u3 was corrected. The corrected package version was 4.2+dfsg-0.1+deb7u4.

For completeness the text from DLA 680-1 available below with only corrected version information. No other changes.

An old attack vector has been corrected in bash (a sh-compatible command language interpreter).

CVE-2016-7543

Specially crafted SHELLOPTS+PS4 environment variables in combination with insecure setuid binaries.

The setuid binary had to both use setuid() function call in combination with a system() or popen() function call. With this combination it is possible to gain root access.

I addition bash have to be the default shell (/bin/sh have to point to bash) for the system to be vulnerable.

The default shell in Debian is dash and there are no known setuid binaries in Debian with the, above described, insecure combination.

There could however be local software with the, above described, insecure combination that could benefit from this correction.

For Debian 7 Wheezy, this problem have been fixed in version 4.2+dfsg-0.1+deb7u4.

We recommend that you upgrade your bash packages.

If there are local software that have the insecure combination and do a setuid() to some other user than root, then the update will not correct that problem. That problem have to be addressed in the insecure setuid binary.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'bash' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"bash-builtins", ver:"4.2+dfsg-0.1+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bash-doc", ver:"4.2+dfsg-0.1+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bash-static", ver:"4.2+dfsg-0.1+deb7u4", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bash", ver:"4.2+dfsg-0.1+deb7u4", rls:"DEB7"))) {
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
