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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3959.1");
  script_cve_id("CVE-2011-5325", "CVE-2015-9261", "CVE-2016-2147", "CVE-2016-2148", "CVE-2016-6301", "CVE-2017-15873", "CVE-2017-15874", "CVE-2017-16544", "CVE-2018-1000500", "CVE-2018-1000517", "CVE-2018-20679", "CVE-2019-5747", "CVE-2021-28831", "CVE-2021-42373", "CVE-2021-42374", "CVE-2021-42375", "CVE-2021-42376", "CVE-2021-42377", "CVE-2021-42378", "CVE-2021-42379", "CVE-2021-42380", "CVE-2021-42381", "CVE-2021-42382", "CVE-2021-42383", "CVE-2021-42384", "CVE-2021-42385", "CVE-2021-42386");
  script_tag(name:"creation_date", value:"2022-11-14 04:33:56 +0000 (Mon, 14 Nov 2022)");
  script_version("2022-11-14T04:33:56+0000");
  script_tag(name:"last_modification", value:"2022-11-14 04:33:56 +0000 (Mon, 14 Nov 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-17 19:41:00 +0000 (Wed, 17 Nov 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3959-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3959-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223959-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'busybox' package(s) announced via the SUSE-SU-2022:3959-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for busybox fixes the following issues:

Enable switch_root With this change virtme --force-initramfs works as
 expected.

Enable udhcpc

busybox was updated to 1.35.0

Adjust busybox.config for new features in find, date and cpio

Annotate CVEs already fixed in upstream, but not mentioned in .changes
 yet:

CVE-2017-16544 (bsc#1069412): Insufficient sanitization of filenames
 when autocompleting

CVE-2015-9261 (bsc#1102912): huft_build misuses a pointer, causing
 segfaults

CVE-2016-2147 (bsc#970663): out of bounds write (heap) due to integer
 underflow in udhcpc

CVE-2016-2148 (bsc#970662): heap-based buffer overflow in OPTION_6RD
 parsing

CVE-2016-6301 (bsc#991940): NTP server denial of service flaw

CVE-2017-15873 (bsc#1064976): The get_next_block function in
 archival/libarchive/decompress_bunzip2.c has an Integer Overflow

CVE-2017-15874 (bsc#1064978): archival/libarchive/decompress_unlzma.c
 has an Integer Underflow

CVE-2019-5747 (bsc#1121428): out of bounds read in udhcp components

CVE-2021-42373, CVE-2021-42374, CVE-2021-42375, CVE-2021-42376,
 CVE-2021-42377, CVE-2021-42378, CVE-2021-42379, CVE-2021-42380,
 CVE-2021-42381, CVE-2021-42382, CVE-2021-42383, CVE-2021-42384,
 CVE-2021-42385, CVE-2021-42386 (bsc#1192869) : v1.34.0 bugfixes

CVE-2021-28831 (bsc#1184522): invalid free or segmentation fault via
 malformed gzip data

CVE-2018-20679 (bsc#1121426): out of bounds read in udhcp

CVE-2018-1000517 (bsc#1099260): Heap-based buffer overflow in the
 retrieve_file_data()

CVE-2011-5325 (bsc#951562): tar directory traversal

CVE-2018-1000500 (bsc#1099263): wget: Missing SSL certificate validation");

  script_tag(name:"affected", value:"'busybox' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"busybox", rpm:"busybox~1.35.0~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busybox-static", rpm:"busybox-static~1.35.0~150400.3.3.1", rls:"SLES15.0SP4"))) {
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
