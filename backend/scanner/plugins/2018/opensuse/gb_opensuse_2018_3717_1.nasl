###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_3717_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for libarchive openSUSE-SU-2018:3717-1 (libarchive)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852119");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2016-10209", "CVE-2016-10349", "CVE-2016-10350", "CVE-2017-14166",
                "CVE-2017-14501", "CVE-2017-14502", "CVE-2017-14503");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-10 05:59:19 +0100 (Sat, 10 Nov 2018)");
  script_name("SuSE Update for libarchive openSUSE-SU-2018:3717-1 (libarchive)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-11/msg00017.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive'
  package(s) announced via the openSUSE-SU-2018:3717_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libarchive fixes the following issues:

  - CVE-2016-10209: The archive_wstring_append_from_mbs function in
  archive_string.c allowed remote attackers to cause a denial of service
  (NULL pointer dereference and application crash) via a crafted archive
  file. (bsc#1032089)

  - CVE-2016-10349: The archive_le32dec function in archive_endian.h allowed
  remote attackers to cause a denial of service (heap-based buffer
  over-read and application crash) via a crafted file. (bsc#1037008)

  - CVE-2016-10350: The archive_read_format_cab_read_header function in
  archive_read_support_format_cab.c allowed remote attackers to cause a
  denial of service (heap-based buffer over-read and application crash)
  via a crafted file. (bsc#1037009)

  - CVE-2017-14166: libarchive allowed remote attackers to cause a denial of
  service (xml_data heap-based buffer over-read and application crash) via
  a crafted xar archive, related to the mishandling of empty strings in
  the atol8 function in archive_read_support_format_xar.c. (bsc#1057514)

  - CVE-2017-14501: An out-of-bounds read flaw existed in parse_file_info in
  archive_read_support_format_iso9660.c when extracting a specially
  crafted iso9660 iso file, related to
  archive_read_format_iso9660_read_header. (bsc#1059139)

  - CVE-2017-14502: read_header in archive_read_support_format_rar.c
  suffered from an off-by-one error for UTF-16 names in RAR archives,
  leading to an out-of-bounds read in archive_read_format_rar_read_header.
  (bsc#1059134)

  - CVE-2017-14503: libarchive suffered from an out-of-bounds read within
  lha_read_data_none() in archive_read_support_format_lha.c when
  extracting a specially crafted lha archive, related to lha_crc16.
  (bsc#1059100)


  This update was imported from the SUSE:SLE-12:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1366=1");

  script_tag(name:"affected", value:"libarchive on openSUSE Leap 42.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"bsdtar", rpm:"bsdtar~3.1.2~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bsdtar-debuginfo", rpm:"bsdtar-debuginfo~3.1.2~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libarchive-debugsource", rpm:"libarchive-debugsource~3.1.2~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libarchive-devel", rpm:"libarchive-devel~3.1.2~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libarchive13", rpm:"libarchive13~3.1.2~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libarchive13-debuginfo", rpm:"libarchive13-debuginfo~3.1.2~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libarchive13-32bit", rpm:"libarchive13-32bit~3.1.2~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libarchive13-debuginfo-32bit", rpm:"libarchive13-debuginfo-32bit~3.1.2~20.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
