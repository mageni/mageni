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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0002");
  script_cve_id("CVE-2022-23468", "CVE-2022-23477", "CVE-2022-23478", "CVE-2022-23479", "CVE-2022-23480", "CVE-2022-23481", "CVE-2022-23482", "CVE-2022-23483", "CVE-2022-23484");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-03-28T10:09:39+0000");
  script_tag(name:"last_modification", value:"2023-03-28 10:09:39 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-10 02:15:00 +0000 (Sat, 10 Dec 2022)");

  script_name("Mageia: Security Advisory (MGASA-2023-0002)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0002");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0002.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31309");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/67CHZVOMSTH2Q7P3TYFUNZUA6J7ZYEBQ/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xrdp' package(s) announced via the MGASA-2023-0002 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"xrdp less than v0.9.21 contain a buffer over flow in
xrdp_login_wnd_create() function. (CVE-2022-23468)

xrdp less than v0.9.21 contain a buffer over flow in audin_send_open()
function. (CVE-2022-23477)

xrdp less than v0.9.21 contain a Out of Bound Write in
xrdp_mm_trans_process_drdynvc_channel_open() function. (CVE-2022-23478)

xrdp less than v0.9.21 contain a buffer over flow in
xrdp_mm_chan_data_in() function. (CVE-2022-23479)

xrdp less than v0.9.21 contain a buffer over flow in
devredir_proc_client_devlist_announce_req() function. (CVE-2022-23480)

xrdp less than v0.9.21 contain a Out of Bound Read in
xrdp_caps_process_confirm_active() function. (CVE-2022-23481)

xrdp less than v0.9.21 contain a Out of Bound Read in
xrdp_sec_process_mcs_data_CS_CORE() function. (CVE-2022-23482)

xrdp less than v0.9.21 contain a Out of Bound Read in
libxrdp_send_to_channel() function. (CVE-2022-23483)

xrdp less than v0.9.21 contain a Integer Overflow in
xrdp_mm_process_rail_update_window_text() function. (CVE-2022-23484)

xrdp less than v0.9.21 contain a Out of Bound Read in
xrdp_mm_trans_process_drdynvc_channel_close() function. (CVE-2022-23493)");

  script_tag(name:"affected", value:"'xrdp' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"xrdp", rpm:"xrdp~0.9.21~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xrdp-devel", rpm:"xrdp-devel~0.9.21~1.mga8", rls:"MAGEIA8"))) {
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
