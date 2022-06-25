# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891728");
  script_version("2019-03-27T09:22:54+0000");
  script_cve_id("CVE-2018-20685", "CVE-2019-6109", "CVE-2019-6111");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-03-27 09:22:54 +0000 (Wed, 27 Mar 2019)");
  script_tag(name:"creation_date", value:"2019-03-25 23:00:00 +0100 (Mon, 25 Mar 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1728-1] openssh security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00030.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1728-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh'
  package(s) announced via the DSA-1728-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple scp client vulnerabilities have been discovered in OpenSSH, the
premier connectivity tool for secure remote shell login and secure file
transfer.

CVE-2018-20685

In scp.c, the scp client allowed remote SSH servers to bypass
intended access restrictions via the filename of . or an empty
filename. The impact was modifying the permissions of the target
directory on the client side.

CVE-2019-6109

Due to missing character encoding in the progress display, a
malicious server (or Man-in-The-Middle attacker) was able to employ
crafted object names to manipulate the client output, e.g., by using
ANSI control codes to hide additional files being transferred. This
affected refresh_progress_meter() in progressmeter.c.

CVE-2019-6111

Due to the scp implementation being derived from 1983 rcp, the server
chooses which files/directories are sent to the client. However, the
scp client only performed cursory validation of the object name
returned (only directory traversal attacks are prevented). A
malicious scp server (or Man-in-The-Middle attacker) was able to
overwrite arbitrary files in the scp client target directory. If
recursive operation (-r) was performed, the server was able to
manipulate subdirectories, as well (for example, to overwrite the
.ssh/authorized_keys file).");

  script_tag(name:"affected", value:"'openssh' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1:6.7p1-5+deb8u8.

We recommend that you upgrade your openssh packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"openssh-client", ver:"1:6.7p1-5+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssh-server", ver:"1:6.7p1-5+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"openssh-sftp-server", ver:"1:6.7p1-5+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssh", ver:"1:6.7p1-5+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"1:6.7p1-5+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ssh-krb5", ver:"1:6.7p1-5+deb8u8", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);