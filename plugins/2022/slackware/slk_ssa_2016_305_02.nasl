# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2016.305.02");
  script_cve_id("CVE-2016-5407", "CVE-2016-7942", "CVE-2016-7943", "CVE-2016-7944", "CVE-2016-7945", "CVE-2016-7946", "CVE-2016-7947", "CVE-2016-7948", "CVE-2016-7949", "CVE-2016-7950", "CVE-2016-7951", "CVE-2016-7952", "CVE-2016-7953");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-05-05T07:49:10+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:30:00 +0000 (Sat, 01 Jul 2017)");

  script_name("Slackware: Security Advisory (SSA:2016-305-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(13\.0|13\.1|13\.37|14\.0|14\.1|14\.2)");

  script_xref(name:"Advisory-ID", value:"SSA:2016-305-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2016&m=slackware-security.3362343");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'x11' package(s) announced via the SSA:2016-305-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New x11 packages are available for Slackware 13.0, 13.1, 13.37, 14.0, 14.1,
14.2, and -current to fix security issues.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/libX11-1.6.4-i586-1_slack14.2.txz: Upgraded.
 Insufficient validation of data from the X server can cause out of boundary
 memory read in XGetImage() or write in XListFonts().
 Affected versions libX11 <= 1.6.3.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
patches/packages/libXfixes-5.0.3-i586-1_slack14.2.txz: Upgraded.
 Insufficient validation of data from the X server can cause an integer
 overflow on 32 bit architectures.
 Affected versions : libXfixes <= 5.0.2.
 For more information, see:
 [link moved to references]
 (* Security fix *)
patches/packages/libXi-1.7.8-i586-1_slack14.2.txz: Upgraded.
 Insufficient validation of data from the X server can cause out of boundary
 memory access or endless loops (Denial of Service).
 Affected versions libXi <= 1.7.6.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
patches/packages/libXrandr-1.5.1-i586-1_slack14.2.txz: Upgraded.
 Insufficient validation of data from the X server can cause out of boundary
 memory writes.
 Affected versions: libXrandr <= 1.5.0.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
patches/packages/libXrender-0.9.10-i586-1_slack14.2.txz: Upgraded.
 Insufficient validation of data from the X server can cause out of boundary
 memory writes.
 Affected version: libXrender <= 0.9.9.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
patches/packages/libXtst-1.2.3-i586-1_slack14.2.txz: Upgraded.
 Insufficient validation of data from the X server can cause out of boundary
 memory access or endless loops (Denial of Service).
 Affected version libXtst <= 1.2.2.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
patches/packages/libXv-1.0.11-i586-1_slack14.2.txz: Upgraded.
 Insufficient validation of data from the X server can cause out of boundary
 memory and memory corruption.
 Affected version libXv <= 1.0.10.
 For more information, see:
 [link moved to references]
 (* Security fix *)
patches/packages/libXvMC-1.0.10-i586-1_slack14.2.txz: Upgraded.
 Insufficient validation of data from the X server can cause a one byte ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'x11' package(s) on Slackware 13.0, Slackware 13.1, Slackware 13.37, Slackware 14.0, Slackware 14.1, Slackware 14.2, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"fixesproto", ver:"5.0-i486-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"fixesproto", ver:"5.0-x86_64-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"inputproto", ver:"2.3.2-noarch-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libX11", ver:"1.6.4-i486-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libX11", ver:"1.6.4-x86_64-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXext", ver:"1.3.3-i486-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXext", ver:"1.3.3-x86_64-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXfixes", ver:"5.0.3-i486-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXfixes", ver:"5.0.3-x86_64-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXi", ver:"1.7.8-i486-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXi", ver:"1.7.8-x86_64-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrandr", ver:"1.5.1-i486-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrandr", ver:"1.5.1-x86_64-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrender", ver:"0.9.10-i486-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrender", ver:"0.9.10-x86_64-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXtst", ver:"1.2.3-i486-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXtst", ver:"1.2.3-x86_64-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXv", ver:"1.0.11-i486-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXv", ver:"1.0.11-x86_64-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXvMC", ver:"1.0.10-i486-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXvMC", ver:"1.0.10-x86_64-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxcb", ver:"1.11.1-i486-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxcb", ver:"1.11.1-x86_64-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"randrproto", ver:"1.5.0-noarch-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"recordproto", ver:"1.14.2-noarch-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xcb-proto", ver:"1.11-i486-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xcb-proto", ver:"1.11-x86_64-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xextproto", ver:"7.3.0-i486-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xextproto", ver:"7.3.0-x86_64-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xproto", ver:"7.0.29-noarch-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"fixesproto", ver:"5.0-i486-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"fixesproto", ver:"5.0-x86_64-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"inputproto", ver:"2.3.2-noarch-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libX11", ver:"1.6.4-i486-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libX11", ver:"1.6.4-x86_64-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXext", ver:"1.3.3-i486-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXext", ver:"1.3.3-x86_64-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXfixes", ver:"5.0.3-i486-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXfixes", ver:"5.0.3-x86_64-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXi", ver:"1.7.8-i486-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXi", ver:"1.7.8-x86_64-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrandr", ver:"1.5.1-i486-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrandr", ver:"1.5.1-x86_64-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrender", ver:"0.9.10-i486-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrender", ver:"0.9.10-x86_64-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXtst", ver:"1.2.3-i486-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXtst", ver:"1.2.3-x86_64-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXv", ver:"1.0.11-i486-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXv", ver:"1.0.11-x86_64-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXvMC", ver:"1.0.10-i486-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXvMC", ver:"1.0.10-x86_64-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxcb", ver:"1.11.1-i486-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxcb", ver:"1.11.1-x86_64-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"randrproto", ver:"1.5.0-noarch-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"recordproto", ver:"1.14.2-noarch-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xcb-proto", ver:"1.11-i486-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xcb-proto", ver:"1.11-x86_64-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xextproto", ver:"7.3.0-i486-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xextproto", ver:"7.3.0-x86_64-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xproto", ver:"7.0.29-noarch-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"inputproto", ver:"2.3.2-noarch-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libX11", ver:"1.6.4-i486-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libX11", ver:"1.6.4-x86_64-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXext", ver:"1.3.3-i486-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXext", ver:"1.3.3-x86_64-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXfixes", ver:"5.0.3-i486-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXfixes", ver:"5.0.3-x86_64-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXi", ver:"1.7.8-i486-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXi", ver:"1.7.8-x86_64-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrandr", ver:"1.5.1-i486-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrandr", ver:"1.5.1-x86_64-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrender", ver:"0.9.10-i486-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrender", ver:"0.9.10-x86_64-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXtst", ver:"1.2.3-i486-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXtst", ver:"1.2.3-x86_64-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXv", ver:"1.0.11-i486-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXv", ver:"1.0.11-x86_64-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXvMC", ver:"1.0.10-i486-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXvMC", ver:"1.0.10-x86_64-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxcb", ver:"1.11.1-i486-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxcb", ver:"1.11.1-x86_64-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"randrproto", ver:"1.5.0-noarch-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"recordproto", ver:"1.14.2-noarch-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xcb-proto", ver:"1.11-i486-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xcb-proto", ver:"1.11-x86_64-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xextproto", ver:"7.3.0-i486-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xextproto", ver:"7.3.0-x86_64-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xproto", ver:"7.0.29-noarch-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"inputproto", ver:"2.3.2-noarch-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libX11", ver:"1.6.4-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libX11", ver:"1.6.4-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXext", ver:"1.3.3-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXext", ver:"1.3.3-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXfixes", ver:"5.0.3-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXfixes", ver:"5.0.3-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXi", ver:"1.7.8-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXi", ver:"1.7.8-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrandr", ver:"1.5.1-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrandr", ver:"1.5.1-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrender", ver:"0.9.10-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrender", ver:"0.9.10-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXtst", ver:"1.2.3-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXtst", ver:"1.2.3-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXv", ver:"1.0.11-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXv", ver:"1.0.11-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXvMC", ver:"1.0.10-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXvMC", ver:"1.0.10-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxcb", ver:"1.11.1-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxcb", ver:"1.11.1-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"randrproto", ver:"1.5.0-noarch-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xcb-proto", ver:"1.11-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xcb-proto", ver:"1.11-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xextproto", ver:"7.3.0-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xextproto", ver:"7.3.0-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xproto", ver:"7.0.29-noarch-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"inputproto", ver:"2.3.2-noarch-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libX11", ver:"1.6.4-i486-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libX11", ver:"1.6.4-x86_64-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXext", ver:"1.3.3-i486-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXext", ver:"1.3.3-x86_64-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXfixes", ver:"5.0.3-i486-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXfixes", ver:"5.0.3-x86_64-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXi", ver:"1.7.8-i486-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXi", ver:"1.7.8-x86_64-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrandr", ver:"1.5.1-i486-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrandr", ver:"1.5.1-x86_64-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrender", ver:"0.9.10-i486-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrender", ver:"0.9.10-x86_64-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXtst", ver:"1.2.3-i486-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXtst", ver:"1.2.3-x86_64-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXv", ver:"1.0.11-i486-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXv", ver:"1.0.11-x86_64-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXvMC", ver:"1.0.10-i486-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXvMC", ver:"1.0.10-x86_64-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxcb", ver:"1.11.1-i486-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxcb", ver:"1.11.1-x86_64-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"randrproto", ver:"1.5.0-noarch-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xcb-proto", ver:"1.11-i486-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xcb-proto", ver:"1.11-x86_64-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xextproto", ver:"7.3.0-i486-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xextproto", ver:"7.3.0-x86_64-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"xproto", ver:"7.0.29-noarch-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libX11", ver:"1.6.4-i586-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libX11", ver:"1.6.4-x86_64-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXfixes", ver:"5.0.3-i586-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXfixes", ver:"5.0.3-x86_64-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXi", ver:"1.7.8-i586-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXi", ver:"1.7.8-x86_64-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrandr", ver:"1.5.1-i586-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrandr", ver:"1.5.1-x86_64-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrender", ver:"0.9.10-i586-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXrender", ver:"0.9.10-x86_64-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXtst", ver:"1.2.3-i586-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXtst", ver:"1.2.3-x86_64-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXv", ver:"1.0.11-i586-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXv", ver:"1.0.11-x86_64-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXvMC", ver:"1.0.10-i586-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libXvMC", ver:"1.0.10-x86_64-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);
