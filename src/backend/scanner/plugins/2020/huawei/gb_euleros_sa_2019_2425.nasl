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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2425");
  script_version("2020-01-23T15:31:18+0000");
  script_cve_id("CVE-2015-8712", "CVE-2015-8713", "CVE-2015-8714", "CVE-2015-8716", "CVE-2015-8717", "CVE-2015-8718", "CVE-2015-8719", "CVE-2015-8721", "CVE-2015-8723", "CVE-2015-8729", "CVE-2015-8731", "CVE-2016-2523", "CVE-2016-2530", "CVE-2016-2531", "CVE-2016-2532", "CVE-2016-4006", "CVE-2016-4077", "CVE-2016-4081", "CVE-2016-4085", "CVE-2016-5350", "CVE-2016-5353", "CVE-2016-5359", "CVE-2016-6505", "CVE-2016-6507", "CVE-2016-6508", "CVE-2016-6510", "CVE-2016-7177", "CVE-2016-7179", "CVE-2016-7958", "CVE-2016-9375", "CVE-2017-13765", "CVE-2017-17083", "CVE-2017-7703", "CVE-2017-9345", "CVE-2017-9347", "CVE-2017-9349", "CVE-2017-9352", "CVE-2018-14340", "CVE-2018-14341", "CVE-2018-16057", "CVE-2018-19622", "CVE-2018-5336", "CVE-2018-7418");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-01-23 15:31:18 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 12:54:39 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for wireshark (EulerOS-SA-2019-2425)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2425");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'wireshark' package(s) announced via the EulerOS-SA-2019-2425 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Wireshark 2.6.0 to 2.6.1, 2.4.0 to 2.4.7, and 2.2.0 to 2.2.15, dissectors that support zlib decompression could crash. This was addressed in epan/tvbuff_zlib.c by rejecting negative lengths to avoid a buffer over-read.(CVE-2018-14340)

In Wireshark 2.6.0 to 2.6.1, 2.4.0 to 2.4.7, and 2.2.0 to 2.2.15, the DICOM dissector could go into a large or infinite loop. This was addressed in epan/dissectors/packet-dcm.c by preventing an offset overflow.(CVE-2018-14341)

In Wireshark 2.4.0 to 2.4.3 and 2.2.0 to 2.2.11, the JSON, XML, NTP, XMPP, and GDB dissectors could crash. This was addressed in epan/tvbparse.c by limiting the recursion depth.(CVE-2018-5336)

In Wireshark 2.2.0 to 2.2.12 and 2.4.0 to 2.4.4, the SIGCOMP dissector could crash. This was addressed in epan/dissectors/packet-sigcomp.c by correcting the extraction of the length value.(CVE-2018-7418)

In Wireshark 2.2.0 to 2.2.6, the ROS dissector could crash with a NULL pointer dereference. This was addressed in epan/dissectors/asn1/ros/packet-ros-template.c by validating an OID.(CVE-2017-9347)

In Wireshark 2.2.0 to 2.2.6 and 2.0.0 to 2.0.12, the DICOM dissector has an infinite loop. This was addressed in epan/dissectors/packet-dcm.c by validating a length value.(CVE-2017-9349)

In Wireshark 2.6.0 to 2.6.1, 2.4.0 to 2.4.7, and 2.2.0 to 2.2.15, dissectors that support zlib decompression could crash. This was addressed in epan/tvbuff_zlib.c by rejecting negative lengths to avoid a buffer over-read.(CVE-2018-14340)

In Wireshark 2.6.0 to 2.6.1, 2.4.0 to 2.4.7, and 2.2.0 to 2.2.15, the DICOM dissector could go into a large or infinite loop. This was addressed in epan/dissectors/packet-dcm.c by preventing an offset overflow.(CVE-2018-14341)

In Wireshark 2.6.0 to 2.6.4 and 2.4.0 to 2.4.10, the MMSE dissector could go into an infinite loop. This was addressed in epan/dissectors/packet-mmse.c by preventing length overflows.(CVE-2018-19622)

The dissect_dcom_OBJREF function in epan/dissectors/packet-dcom.c in the DCOM dissector in Wireshark 1.12.x before 1.12.9 does not initialize a certain IPv4 data structure, which allows remote attackers to cause a denial of service (application crash) via a crafted packet.(CVE-2015-8714)

In Wireshark 2.4.0, 2.2.0 to 2.2.8, and 2.0.0 to 2.0.14, the IrCOMM dissector has a buffer over-read and application crash. This was addressed in plugins/irda/packet-ircomm.c by adding length validation.(CVE-2017-13765)

In Wireshark 2.4.0 to 2.4.2 and 2.2.0 to 2.2.10, the NetBIOS dissector could crash. This was addressed in epan/dissectors/packet-netbios.c by ensuring that write operations are bounded by the beginning  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'wireshark' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.10.14~7.h12", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.10.14~7.h12", rls:"EULEROS-2.0SP2"))) {
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
