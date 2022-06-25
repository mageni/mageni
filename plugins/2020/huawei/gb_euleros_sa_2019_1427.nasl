# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1427");
  script_version("2020-01-23T11:45:01+0000");
  script_cve_id("CVE-2010-0743", "CVE-2010-2221");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 11:45:01 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:45:01 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for scsi-target-utils (EulerOS-SA-2019-1427)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.1\.0");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1427");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'scsi-target-utils' package(s) announced via the EulerOS-SA-2019-1427 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple buffer overflows in the iSNS implementation in isns.c in (1) Linux SCSI target framework (aka tgt or scsi-target-utils) before 1.0.6, (2) iSCSI Enterprise Target (aka iscsitarget or IET) 1.4.20.1 and earlier, and (3) Generic SCSI Target Subsystem for Linux (aka SCST or iscsi-scst) 1.0.1.1 and earlier allow remote attackers to cause a denial of service (memory corruption and daemon crash) or possibly execute arbitrary code via (a) a long iSCSI Name string in an SCN message or (b) an invalid PDU.(CVE-2010-2221)

Multiple format string vulnerabilities in isns.c in (1) Linux SCSI target framework (aka tgt or scsi-target-utils) 1.0.3, 0.9.5, and earlier and (2) iSCSI Enterprise Target (aka iscsitarget) 0.4.16 allow remote attackers to cause a denial of service (tgtd daemon crash) or possibly have unspecified other impact via vectors that involve the isns_attr_query and qry_rsp_handle functions, and are related to (a) client appearance and (b) client disappearance messages.(CVE-2010-0743)");

  script_tag(name:"affected", value:"'scsi-target-utils' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"scsi-target-utils", rpm:"scsi-target-utils~1.0.70~4.h3", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);