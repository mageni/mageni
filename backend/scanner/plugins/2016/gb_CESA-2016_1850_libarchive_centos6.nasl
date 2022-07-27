###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libarchive CESA-2016:1850 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882557");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-09-16 05:42:09 +0200 (Fri, 16 Sep 2016)");
  script_cve_id("CVE-2015-8920", "CVE-2015-8921", "CVE-2015-8932", "CVE-2016-4809",
                "CVE-2016-5418", "CVE-2016-5844", "CVE-2016-7166");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for libarchive CESA-2016:1850 centos6");
  script_tag(name:"summary", value:"Check the version of libarchive");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The libarchive programming library can
create and read several different streaming archive formats, including GNU tar,
cpio and ISO 9660 CD-ROM images. Libarchive is used notably in the bsdtar
utility, scripting language bindings such as python-libarchive, and several
popular desktop file managers.

Security Fix(es):

  * A flaw was found in the way libarchive handled hardlink archive entries
of non-zero size. Combined with flaws in libarchive's file system
sandboxing, this issue could cause an application using libarchive to
overwrite arbitrary files with arbitrary data from the archive.
(CVE-2016-5418)

  * Multiple out-of-bounds read flaws were found in libarchive. Specially
crafted AR or MTREE files could cause the application to read data out of
bounds, potentially disclosing a small amount of application memory, or
causing an application crash. (CVE-2015-8920, CVE-2015-8921)

  * A denial of service vulnerability was found in libarchive's handling of
GZIP streams. A crafted GZIP file could cause libarchive to allocate an
excessive amount of memory, eventually leading to a crash. (CVE-2016-7166)

  * A denial of service vulnerability was found in libarchive. A specially
crafted CPIO archive containing a symbolic link to a large target path
could cause memory allocation to fail, causing an application using
libarchive that attempted to view or extract such archive to crash.
(CVE-2016-4809)

  * Multiple instances of undefined behavior due to arithmetic overflow were
found in libarchive. Specially crafted Compress streams or ISO9660 volumes
could potentially cause the application to fail to read the archive, or to
crash. (CVE-2015-8932, CVE-2016-5844)

Red Hat would like to thank Insomnia Security for reporting CVE-2016-5418.");
  script_tag(name:"affected", value:"libarchive on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-September/022067.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"libarchive", rpm:"libarchive~2.8.3~7.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libarchive-devel", rpm:"libarchive-devel~2.8.3~7.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
