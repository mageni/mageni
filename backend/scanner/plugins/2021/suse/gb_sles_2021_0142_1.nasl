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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0142.1");
  script_cve_id("CVE-2020-25709", "CVE-2020-25710");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:45 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-06-09T14:56:45+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-24 19:55:00 +0000 (Mon, 24 May 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0142-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0142-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210142-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap2' package(s) announced via the SUSE-SU-2021:0142-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openldap2 fixes the following issues:

CVE-2020-25709: Fixed a crash caused by specially crafted network
 traffic (bsc#1178909).

CVE-2020-25710: Fixed a crash caused by specially crafted network
 traffic (bsc#1178909).");

  script_tag(name:"affected", value:"'openldap2' package(s) on SUSE Linux Enterprise Server for SAP 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Module for Legacy Software 12");

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

if(release == "SLES12.0") {
  if(!isnull(res = isrpmvuln(pkg:"compat-libldap-2_3-0", rpm:"compat-libldap-2_3-0~2.3.37~18.24.26.1", rls:"SLES12.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"compat-libldap-2_3-0-debuginfo", rpm:"compat-libldap-2_3-0-debuginfo~2.3.37~18.24.26.1", rls:"SLES12.0"))){
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
