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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0374.1");
  script_cve_id("CVE-2022-23468", "CVE-2022-23478", "CVE-2022-23479", "CVE-2022-23480", "CVE-2022-23481", "CVE-2022-23482", "CVE-2022-23483", "CVE-2022-23484", "CVE-2022-23493");
  script_tag(name:"creation_date", value:"2023-02-13 04:19:57 +0000 (Mon, 13 Feb 2023)");
  script_version("2023-02-13T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-02-13 10:09:19 +0000 (Mon, 13 Feb 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-10 02:15:00 +0000 (Sat, 10 Dec 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0374-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0374-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230374-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xrdp' package(s) announced via the SUSE-SU-2023:0374-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xrdp fixes the following issues:

CVE-2022-23468: Fixed a buffer overflow in xrdp_login_wnd_create()
 (bsc#1206300).

CVE-2022-23478: Fixed an out of bound write in
 xrdp_mm_trans_process_drdynvc_chan() (bsc#1206302).

CVE-2022-23479: Fixed a buffer overflow in xrdp_mm_chan_data_in()
 (bsc#1206303).

CVE-2022-23480: Fixed a buffer overflow in
 devredir_proc_client_devlist_announce_req() (bsc#1206306).

CVE-2022-23481: Fixed an out of bound read in
 xrdp_caps_process_confirm_active() (bsc#1206307).

CVE-2022-23482: Fixed an out of bound read in
 xrdp_sec_process_mcs_data_CS_CORE() (bsc#1206310, bsc#1206621).

CVE-2022-23483: Fixed an out of bound read in libxrdp_send_to_channel()
 (bsc#1206311).

CVE-2022-23484: Fixed a integer overflow in
 xrdp_mm_process_rail_update_window_text() (bsc#1206312).

CVE-2022-23493: Fixed an out of bound read in
 xrdp_mm_trans_process_drdynvc_channel_close() (bsc#1206313).");

  script_tag(name:"affected", value:"'xrdp' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"xrdp", rpm:"xrdp~0.9.10~3.8.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp-debuginfo", rpm:"xrdp-debuginfo~0.9.10~3.8.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp-debugsource", rpm:"xrdp-debugsource~0.9.10~3.8.1", rls:"SLES12.0SP5"))) {
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
