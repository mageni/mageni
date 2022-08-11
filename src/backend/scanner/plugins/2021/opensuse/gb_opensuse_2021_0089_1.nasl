# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853683");
  script_version("2021-04-21T07:29:02+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 04:59:57 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for open-iscsi (openSUSE-SU-2021:0089-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0089-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5AAKYHQ4YQUHU54P5YEWAIU5PIP327GF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'open-iscsi'
  package(s) announced via the openSUSE-SU-2021:0089-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for open-iscsi fixes the following issues:

  - Updated to upstream version 2.1.3 as 2.1.3-suse, for bsc#1179908,
       including:

  * uip: check for TCP urgent pointer past end of frame

  * uip: check for u8 overflow when processing TCP options

  * uip: check for header length underflow during checksum calculation

  * fwparam_ppc: Fix memory leak in fwparam_ppc.c

  * iscsiuio: Remove unused macro IFNAMSIZ defined in iscsid_ipc.c

  * fwparam_ppc: Fix illegal memory access in fwparam_ppc.c

  * sysfs: Verify parameter of sysfs_device_get()

  * fwparam_ppc: Fix NULL pointer dereference in find_devtree()

  * open-iscsi: Clean user_param list when process exit

  * iscsi_net_util: Fix NULL pointer dereference in find_vlan_dev()

  * open-iscsi: Fix NULL pointer dereference in mgmt_ipc_read_req()

  * open-iscsi: Fix invalid pointer deference in find_initiator()

  * iscsiuio: Fix invalid parameter when call fstat()

  * iscsi-iname: Verify open() return value before calling read()

  * iscsi_sysfs: Fix NULL pointer deference in iscsi_sysfs_read_iface

  - Updatged to latest upstream

  * iscsid: Poll timeout value to 1 minute for iscsid

  * iscsiadm: fix host stats mode coredump

  * iscsid: fix logging level when starting and shutting down daemon

  * Updated iscsiadm man page.

  * Fix memory leak in sysfs_get_str

  * libopeniscsiusr: Compare with max int instead of max long

  - Systemd unit files should not depend on network.target (bsc#1179440).

  - Updated to latest upstream, including async login ability:

  * Implement login 'no_wait' for iscsiadm NODE mode

  * iscsiadm buffer overflow regression when discovering many targets at
        once

  * iscsid: Check Invalid Session id for stop connection

  * Add ability to attempt target logins asynchronously

  - %service_del_postun_without_restart is now available on SLE More
       accurately it&#x27 s been introduced in SLE12-SP2+ and SLE15+

     This update was imported from the SUSE:SLE-15-SP2:Update update project.");

  script_tag(name:"affected", value:"'open-iscsi' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"iscsiuio", rpm:"iscsiuio~0.7.8.6~lp152.18.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iscsiuio-debuginfo", rpm:"iscsiuio-debuginfo~0.7.8.6~lp152.18.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopeniscsiusr0_2_0", rpm:"libopeniscsiusr0_2_0~2.1.3~lp152.18.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopeniscsiusr0_2_0-debuginfo", rpm:"libopeniscsiusr0_2_0-debuginfo~2.1.3~lp152.18.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-iscsi", rpm:"open-iscsi~2.1.3~lp152.18.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-iscsi-debuginfo", rpm:"open-iscsi-debuginfo~2.1.3~lp152.18.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-iscsi-debugsource", rpm:"open-iscsi-debugsource~2.1.3~lp152.18.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-iscsi-devel", rpm:"open-iscsi-devel~2.1.3~lp152.18.6.1", rls:"openSUSELeap15.2"))) {
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
