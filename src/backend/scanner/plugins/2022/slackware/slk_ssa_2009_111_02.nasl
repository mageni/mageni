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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2009.111.02");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-04-26T09:43:38+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2009-111-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK12\.2");

  script_xref(name:"Advisory-ID", value:"SSA:2009-111-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.403301");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'udev' package(s) announced via the SSA:2009-111-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated udev packages are available for Slackware 12.2, and -current to fix
a serial device ownership regression in 12.2, adjust the perms on /dev/rtc0,
and make sure that the /dev/root symlink is properly created.


Here are the details from the Slackware 12.2 ChangeLog:
+--------------------------+
patches/packages/udev-141-i486-2_slack12.2.tgz:
 Fixed a regression with serial/dialout device ownership.
 Slackware 12.2 uses the 'uucp' group for these devices, but the newer
 version of udev has changed them to 'dialout', leading to log errors and
 an incorrect group ownership for serial devices since the 'dialout' group
 does not exist on Slackware 12.2.
 This update changes the serial device group ownership back to 'uucp'.
 Thanks to Alexander Pravdin for the fast bug report.
 Changed the permissions on the real time clock (/dev/rtc0) so that all
 users can read it.
 Modified rc.udev so that the /dev/root symlink is created.
 Thanks to Piter Punk!
+--------------------------+

Here are the details from the Slackware -current ChangeLog:
+--------------------------+
a/udev-141-i486-2.tgz: Changed the permissions on the real time clock
 (/dev/rtc0) so that all users can read it.
 Modified rc.udev so that the /dev/root symlink is created.
 Thanks to Piter Punk!
+--------------------------+");

  script_tag(name:"affected", value:"'udev' package(s) on Slackware 12.2, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"udev", ver:"141-i486-2_slack12.2", rls:"SLK12.2"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);
