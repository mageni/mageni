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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2125.1");
  script_cve_id("CVE-2020-26418", "CVE-2020-26419", "CVE-2020-26420", "CVE-2020-26421", "CVE-2020-26422", "CVE-2021-22173", "CVE-2021-22174", "CVE-2021-22191", "CVE-2021-22207");
  script_tag(name:"creation_date", value:"2021-06-23 06:40:31 +0000 (Wed, 23 Jun 2021)");
  script_version("2021-06-23T06:40:31+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-16 14:02:00 +0000 (Wed, 16 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2125-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0|SLES15\.0SP3|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2125-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212125-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2021:2125-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wireshark, libvirt, sbc and libqt5-qtmultimedia fixes the following issues:

Update wireshark to version 3.4.5

New and updated support and bug fixes for multiple protocols

Asynchronous DNS resolution is always enabled

Protobuf fields can be dissected as Wireshark (header) fields

UI improvements

Including security fixes for:

CVE-2021-22191: Wireshark could open unsafe URLs (bsc#1183353).

CVE-2021-22207: MS-WSP dissector excessive memory consumption
 (bsc#1185128)

CVE-2020-26422: QUIC dissector crash (bsc#1180232)

CVE-2020-26418: Kafka dissector memory leak (bsc#1179930)

CVE-2020-26419: Multiple dissector memory leaks (bsc#1179931)

CVE-2020-26420: RTPS dissector memory leak (bsc#1179932)

CVE-2020-26421: USB HID dissector crash (bsc#1179933)

CVE-2021-22173: Fix USB HID dissector memory leak (bsc#1181598)

CVE-2021-22174: Fix USB HID dissector crash (bsc#1181599)

libqt5-qtmultimedia and sbc are necessary dependencies. libvirt is needed to rebuild wireshark-plugin-libvirt.");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Manager Server 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Proxy 4.0, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Module for Desktop Applications 15-SP3, SUSE Linux Enterprise Module for Desktop Applications 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15, SUSE Enterprise Storage 6, SUSE CaaS Platform 4.0");

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

if(release == "SLES15.0SP1") {
  if(!isnull(res = isrpmvuln(pkg:"libQt5Multimedia5", rpm:"libQt5Multimedia5~5.9.7~7.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Multimedia5-debuginfo", rpm:"libQt5Multimedia5-debuginfo~5.9.7~7.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtmultimedia-debugsource", rpm:"libqt5-qtmultimedia-debugsource~5.9.7~7.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtmultimedia-devel", rpm:"libqt5-qtmultimedia-devel~5.9.7~7.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsbc1", rpm:"libsbc1~1.3~3.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsbc1-debuginfo", rpm:"libsbc1-debuginfo~1.3~3.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark14", rpm:"libwireshark14~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark14-debuginfo", rpm:"libwireshark14-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap11", rpm:"libwiretap11~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap11-debuginfo", rpm:"libwiretap11-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil12", rpm:"libwsutil12~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil12-debuginfo", rpm:"libwsutil12-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbc-debuginfo", rpm:"sbc-debuginfo~1.3~3.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbc-debugsource", rpm:"sbc-debugsource~1.3~3.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbc-devel", rpm:"sbc-devel~1.3~3.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt", rpm:"wireshark-ui-qt~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt-debuginfo", rpm:"wireshark-ui-qt-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtmultimedia-private-headers-devel", rpm:"libqt5-qtmultimedia-private-headers-devel~5.9.7~7.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtmultimedia-private-headers-devel", rpm:"libqt5-qtmultimedia-private-headers-devel~5.9.7~7.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Multimedia5", rpm:"libQt5Multimedia5~5.9.7~7.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Multimedia5-debuginfo", rpm:"libQt5Multimedia5-debuginfo~5.9.7~7.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtmultimedia-debugsource", rpm:"libqt5-qtmultimedia-debugsource~5.9.7~7.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtmultimedia-devel", rpm:"libqt5-qtmultimedia-devel~5.9.7~7.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsbc1", rpm:"libsbc1~1.3~3.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsbc1-debuginfo", rpm:"libsbc1-debuginfo~1.3~3.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark14", rpm:"libwireshark14~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark14-debuginfo", rpm:"libwireshark14-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap11", rpm:"libwiretap11~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap11-debuginfo", rpm:"libwiretap11-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil12", rpm:"libwsutil12~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil12-debuginfo", rpm:"libwsutil12-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbc-debuginfo", rpm:"sbc-debuginfo~1.3~3.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbc-debugsource", rpm:"sbc-debugsource~1.3~3.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbc-devel", rpm:"sbc-devel~1.3~3.2.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt", rpm:"wireshark-ui-qt~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt-debuginfo", rpm:"wireshark-ui-qt-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP1"))){
    report += res;
  }


  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {
  if(!isnull(res = isrpmvuln(pkg:"libsbc1", rpm:"libsbc1~1.3~3.2.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsbc1-debuginfo", rpm:"libsbc1-debuginfo~1.3~3.2.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-admin", rpm:"libvirt-admin~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-admin-debuginfo", rpm:"libvirt-admin-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client-debuginfo", rpm:"libvirt-client-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon", rpm:"libvirt-daemon~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-network", rpm:"libvirt-daemon-config-network~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-nwfilter", rpm:"libvirt-daemon-config-nwfilter~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-debuginfo", rpm:"libvirt-daemon-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-interface", rpm:"libvirt-daemon-driver-interface~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-interface-debuginfo", rpm:"libvirt-daemon-driver-interface-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-lxc", rpm:"libvirt-daemon-driver-lxc~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-lxc-debuginfo", rpm:"libvirt-daemon-driver-lxc-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-network", rpm:"libvirt-daemon-driver-network~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-network-debuginfo", rpm:"libvirt-daemon-driver-network-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nodedev", rpm:"libvirt-daemon-driver-nodedev~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nodedev-debuginfo", rpm:"libvirt-daemon-driver-nodedev-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nwfilter", rpm:"libvirt-daemon-driver-nwfilter~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nwfilter-debuginfo", rpm:"libvirt-daemon-driver-nwfilter-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-qemu", rpm:"libvirt-daemon-driver-qemu~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-qemu-debuginfo", rpm:"libvirt-daemon-driver-qemu-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-secret", rpm:"libvirt-daemon-driver-secret~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-secret-debuginfo", rpm:"libvirt-daemon-driver-secret-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage", rpm:"libvirt-daemon-driver-storage~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-core", rpm:"libvirt-daemon-driver-storage-core~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-core-debuginfo", rpm:"libvirt-daemon-driver-storage-core-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-disk", rpm:"libvirt-daemon-driver-storage-disk~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-disk-debuginfo", rpm:"libvirt-daemon-driver-storage-disk-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-iscsi", rpm:"libvirt-daemon-driver-storage-iscsi~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-iscsi-debuginfo", rpm:"libvirt-daemon-driver-storage-iscsi-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-logical", rpm:"libvirt-daemon-driver-storage-logical~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-logical-debuginfo", rpm:"libvirt-daemon-driver-storage-logical-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-mpath", rpm:"libvirt-daemon-driver-storage-mpath~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-mpath-debuginfo", rpm:"libvirt-daemon-driver-storage-mpath-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-scsi", rpm:"libvirt-daemon-driver-storage-scsi~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-scsi-debuginfo", rpm:"libvirt-daemon-driver-storage-scsi-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-hooks", rpm:"libvirt-daemon-hooks~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-lxc", rpm:"libvirt-daemon-lxc~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-qemu", rpm:"libvirt-daemon-qemu~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-debugsource", rpm:"libvirt-debugsource~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-doc", rpm:"libvirt-doc~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-libs", rpm:"libvirt-libs~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-libs-debuginfo", rpm:"libvirt-libs-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-lock-sanlock-debuginfo", rpm:"libvirt-lock-sanlock-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-nss", rpm:"libvirt-nss~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-nss-debuginfo", rpm:"libvirt-nss-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark14", rpm:"libwireshark14~3.4.5~3.53.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark14-debuginfo", rpm:"libwireshark14-debuginfo~3.4.5~3.53.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap11", rpm:"libwiretap11~3.4.5~3.53.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap11-debuginfo", rpm:"libwiretap11-debuginfo~3.4.5~3.53.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil12", rpm:"libwsutil12~3.4.5~3.53.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil12-debuginfo", rpm:"libwsutil12-debuginfo~3.4.5~3.53.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbc-debuginfo", rpm:"sbc-debuginfo~1.3~3.2.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbc-debugsource", rpm:"sbc-debugsource~1.3~3.2.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbc-devel", rpm:"sbc-devel~1.3~3.2.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~3.4.5~3.53.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~3.4.5~3.53.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~3.4.5~3.53.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~3.4.5~3.53.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt", rpm:"wireshark-ui-qt~3.4.5~3.53.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt-debuginfo", rpm:"wireshark-ui-qt-debuginfo~3.4.5~3.53.1", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-rbd", rpm:"libvirt-daemon-driver-storage-rbd~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage-rbd-debuginfo", rpm:"libvirt-daemon-driver-storage-rbd-debuginfo~4.0.0~9.37.21", rls:"SLES15.0"))){
    report += res;
  }


  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {
  if(!isnull(res = isrpmvuln(pkg:"libsbc1", rpm:"libsbc1~1.3~3.2.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsbc1-debuginfo", rpm:"libsbc1-debuginfo~1.3~3.2.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbc-debuginfo", rpm:"sbc-debuginfo~1.3~3.2.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbc-debugsource", rpm:"sbc-debugsource~1.3~3.2.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbc-devel", rpm:"sbc-devel~1.3~3.2.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~3.4.5~3.53.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~3.4.5~3.53.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt", rpm:"wireshark-ui-qt~3.4.5~3.53.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt-debuginfo", rpm:"wireshark-ui-qt-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsbc1", rpm:"libsbc1~1.3~3.2.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsbc1-debuginfo", rpm:"libsbc1-debuginfo~1.3~3.2.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark14", rpm:"libwireshark14~3.4.5~3.53.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark14-debuginfo", rpm:"libwireshark14-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap11", rpm:"libwiretap11~3.4.5~3.53.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap11-debuginfo", rpm:"libwiretap11-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil12", rpm:"libwsutil12~3.4.5~3.53.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil12-debuginfo", rpm:"libwsutil12-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~3.4.5~3.53.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP3"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~3.4.5~3.53.1", rls:"SLES15.0SP3"))){
    report += res;
  }


  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {
  if(!isnull(res = isrpmvuln(pkg:"libsbc1", rpm:"libsbc1~1.3~3.2.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsbc1-debuginfo", rpm:"libsbc1-debuginfo~1.3~3.2.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbc-debuginfo", rpm:"sbc-debuginfo~1.3~3.2.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbc-debugsource", rpm:"sbc-debugsource~1.3~3.2.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sbc-devel", rpm:"sbc-devel~1.3~3.2.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~3.4.5~3.53.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~3.4.5~3.53.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt", rpm:"wireshark-ui-qt~3.4.5~3.53.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt-debuginfo", rpm:"wireshark-ui-qt-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsbc1", rpm:"libsbc1~1.3~3.2.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsbc1-debuginfo", rpm:"libsbc1-debuginfo~1.3~3.2.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark14", rpm:"libwireshark14~3.4.5~3.53.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark14-debuginfo", rpm:"libwireshark14-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap11", rpm:"libwiretap11~3.4.5~3.53.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap11-debuginfo", rpm:"libwiretap11-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil12", rpm:"libwsutil12~3.4.5~3.53.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil12-debuginfo", rpm:"libwsutil12-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~3.4.5~3.53.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~3.4.5~3.53.1", rls:"SLES15.0SP2"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~3.4.5~3.53.1", rls:"SLES15.0SP2"))){
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
