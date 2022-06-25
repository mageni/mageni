###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1961_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for exiv2 openSUSE-SU-2018:1961-1 (exiv2)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852088");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2017-11337", "CVE-2017-11338", "CVE-2017-11339", "CVE-2017-11340", "CVE-2017-11553", "CVE-2017-11591", "CVE-2017-11592", "CVE-2017-11683", "CVE-2017-12955", "CVE-2017-12956", "CVE-2017-12957", "CVE-2017-14859", "CVE-2017-14860", "CVE-2017-14862", "CVE-2017-14864");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:43:16 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for exiv2 openSUSE-SU-2018:1961-1 (exiv2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-07/msg00019.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2'
  package(s) announced via the openSUSE-SU-2018:1961_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for exiv2 to 0.26 fixes the following security issues:

  - CVE-2017-14864: Prevent invalid memory address dereference in
  Exiv2::getULong that could have caused a segmentation fault and
  application crash, which leads to denial of service (bsc#1060995).

  - CVE-2017-14862: Prevent invalid memory address dereference in
  Exiv2::DataValue::read that could have caused a segmentation fault and
  application crash, which leads to denial of service (bsc#1060996).

  - CVE-2017-14859: Prevent invalid memory address dereference in
  Exiv2::StringValueBase::read that could have caused a segmentation fault
  and application crash, which leads to denial of service (bsc#1061000).

  - CVE-2017-14860: Prevent heap-based buffer over-read in the
  Exiv2::Jp2Image::readMetadata function via a crafted input that could
  have lead to a denial of service attack (bsc#1061023).

  - CVE-2017-11337: Prevent invalid free in the Action::TaskFactory::cleanup
  function via a crafted input that could have lead to a remote denial of
  service attack (bsc#1048883).

  - CVE-2017-11338: Prevent infinite loop in the
  Exiv2::Image::printIFDStructure function via a crafted input that could
  have lead to a remote denial of service attack (bsc#1048883).

  - CVE-2017-11339: Prevent heap-based buffer overflow in the
  Image::printIFDStructure function via a crafted input that could have
  lead to a remote denial of service attack (bsc#1048883).

  - CVE-2017-11340: Prevent Segmentation fault in the XmpParser::terminate()
  function via a crafted input that could have lead to a remote denial of
  service attack (bsc#1048883).

  - CVE-2017-12955: Prevent heap-based buffer overflow. The vulnerability
  caused an out-of-bounds write in Exiv2::Image::printIFDStructure(),
  which may lead to remote denial of service or possibly unspecified other
  impact (bsc#1054593).

  - CVE-2017-12956: Preventn illegal address access in
  Exiv2::FileIo::path[abi:cxx11]() that could have lead to remote denial
  of service (bsc#1054592).

  - CVE-2017-12957: Prevent heap-based buffer over-read that was triggered
  in the Exiv2::Image::io function and could have lead to remote denial of
  service (bsc#1054590).

  - CVE-2017-11683: Prevent reachable assertion in the
  Internal::TiffReader::visitDirectory function that could have lead to a
  remote denial of service attack via crafted input (bsc#1051188).

  - CVE-2017-11591: Prevent Floating point exception in the Exiv2::ValueType
  function that could have lead to a remote denial of service attack via
  crafted input (bsc#1050257).

  - CVE-2017-11553: Prevent illegal address access i ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"exiv2 on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"exiv2", rpm:"exiv2~0.26~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exiv2-debuginfo", rpm:"exiv2-debuginfo~0.26~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exiv2-debugsource", rpm:"exiv2-debugsource~0.26~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libexiv2-26", rpm:"libexiv2-26~0.26~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libexiv2-26-debuginfo", rpm:"libexiv2-26-debuginfo~0.26~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libexiv2-devel", rpm:"libexiv2-devel~0.26~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libexiv2-doc", rpm:"libexiv2-doc~0.26~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libexiv2-26-32bit", rpm:"libexiv2-26-32bit~0.26~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libexiv2-26-32bit-debuginfo", rpm:"libexiv2-26-32bit-debuginfo~0.26~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"exiv2-lang", rpm:"exiv2-lang~0.26~lp150.5.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
