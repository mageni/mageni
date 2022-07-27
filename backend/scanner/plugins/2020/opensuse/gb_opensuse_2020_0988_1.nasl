# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853286");
  script_version("2020-07-24T07:28:01+0000");
  script_cve_id("CVE-2017-18922", "CVE-2018-21247", "CVE-2019-20839", "CVE-2019-20840", "CVE-2020-14397", "CVE-2020-14398", "CVE-2020-14399", "CVE-2020-14400", "CVE-2020-14401", "CVE-2020-14402");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-07-24 10:05:16 +0000 (Fri, 24 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-19 03:01:28 +0000 (Sun, 19 Jul 2020)");
  script_name("openSUSE: Security Advisory for LibVNCServer (openSUSE-SU-2020:0988-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0988-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00033.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'LibVNCServer'
  package(s) announced via the openSUSE-SU-2020:0988-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for LibVNCServer fixes the following issues:

  - security update

  - added patches fix CVE-2018-21247 [bsc#1173874], uninitialized memory
  contents are vulnerable to Information leak
  + LibVNCServer-CVE-2018-21247.patch fix CVE-2019-20839 [bsc#1173875],
  buffer overflow in ConnectClientToUnixSock()
  + LibVNCServer-CVE-2019-20839.patch fix CVE-2019-20840 [bsc#1173876],
  unaligned accesses in hybiReadAndDecode can lead to denial of service
  + LibVNCServer-CVE-2019-20840.patch fix CVE-2020-14398 [bsc#1173880],
  improperly closed TCP connection causes an infinite loop in
  libvncclient/sockets.c
  + LibVNCServer-CVE-2020-14398.patch fix CVE-2020-14397 [bsc#1173700],
  NULL pointer dereference in libvncserver/rfbregion.c
  + LibVNCServer-CVE-2020-14397.patch fix CVE-2020-14399 [bsc#1173743],
  Byte-aligned data is accessed through uint32_t pointers in
  libvncclient/rfbproto.c.
  + LibVNCServer-CVE-2020-14399.patch fix CVE-2020-14400 [bsc#1173691],
  Byte-aligned data is accessed through uint16_t pointers in
  libvncserver/translate.c.
  + LibVNCServer-CVE-2020-14400.patch fix CVE-2020-14401 [bsc#1173694],
  potential integer overflows in libvncserver/scale.c
  + LibVNCServer-CVE-2020-14401.patch fix CVE-2020-14402 [bsc#1173701],
  out-of-bounds access via encodings.
  + LibVNCServer-CVE-2020-14402, 14403, 14404.patch fix CVE-2017-18922
  [bsc#1173477], preauth buffer overwrite

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-988=1");

  script_tag(name:"affected", value:"'LibVNCServer' package(s) on openSUSE Leap 15.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"LibVNCServer-debugsource", rpm:"LibVNCServer-debugsource~0.9.10~lp151.7.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"LibVNCServer-devel", rpm:"LibVNCServer-devel~0.9.10~lp151.7.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncclient0", rpm:"libvncclient0~0.9.10~lp151.7.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncclient0-debuginfo", rpm:"libvncclient0-debuginfo~0.9.10~lp151.7.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver0", rpm:"libvncserver0~0.9.10~lp151.7.9.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver0-debuginfo", rpm:"libvncserver0-debuginfo~0.9.10~lp151.7.9.1", rls:"openSUSELeap15.1"))) {
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