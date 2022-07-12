###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for libarchive RHSA-2016:1844-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871659");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-13 05:45:09 +0200 (Tue, 13 Sep 2016)");
  script_cve_id("CVE-2015-8916", "CVE-2015-8917", "CVE-2015-8919", "CVE-2015-8920",
		"CVE-2015-8921", "CVE-2015-8922", "CVE-2015-8923", "CVE-2015-8924",
		"CVE-2015-8925", "CVE-2015-8926", "CVE-2015-8928", "CVE-2015-8930",
		"CVE-2015-8931", "CVE-2015-8932", "CVE-2015-8934", "CVE-2016-1541",
		"CVE-2016-4300", "CVE-2016-4302", "CVE-2016-4809", "CVE-2016-5418",
		"CVE-2016-5844", "CVE-2016-6250", "CVE-2016-7166");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for libarchive RHSA-2016:1844-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The libarchive programming library can create
  and read several different streaming archive formats, including GNU tar, cpio, and
  ISO 9660 CD-ROM images. Libarchive is used notably in the bsdtar utility, scripting
  language bindings such as python-libarchive, and several popular desktop
  file managers.

Security Fix(es):

  * A flaw was found in the way libarchive handled hardlink archive entries
of non-zero size. Combined with flaws in libarchive's file system
sandboxing, this issue could cause an application using libarchive to
overwrite arbitrary files with arbitrary data from the archive.
(CVE-2016-5418)

  * Multiple out-of-bounds write flaws were found in libarchive. Specially
crafted ZIP, 7ZIP, or RAR files could cause a heap overflow, potentially
allowing code execution in the context of the application using libarchive.
(CVE-2016-1541, CVE-2016-4300, CVE-2016-4302)

  * Multiple out-of-bounds read flaws were found in libarchive. Specially
crafted LZA/LZH, AR, MTREE, ZIP, TAR, or RAR files could cause the
application to read data out of bounds, potentially disclosing a small
amount of application memory, or causing an application crash.
(CVE-2015-8919, CVE-2015-8920, CVE-2015-8921, CVE-2015-8923, CVE-2015-8924,
CVE-2015-8925, CVE-2015-8926, CVE-2015-8928, CVE-2015-8934)

  * Multiple NULL pointer dereference flaws were found in libarchive.
Specially crafted RAR, CAB, or 7ZIP files could cause an application using
libarchive to crash. (CVE-2015-8916, CVE-2015-8917, CVE-2015-8922)

  * Multiple infinite loop / resource exhaustion flaws were found in
libarchive. Specially crafted GZIP or ISO files could cause the application
to consume an excessive amount of resources, eventually leading to a crash
on memory exhaustion. (CVE-2016-7166, CVE-2015-8930)

  * A denial of service vulnerability was found in libarchive. A specially
crafted CPIO archive containing a symbolic link to a large target path
could cause memory allocation to fail, causing an application using
libarchive that attempted to view or extract such archive to crash.
(CVE-2016-4809)

  * An integer overflow flaw, leading to a buffer overflow, was found in
libarchive's construction of ISO9660 volumes. Attempting to create an
ISO9660 volume with 2 GB or 4 GB file names could cause the application to
attempt to allocate 20 GB of memory. If this were to succeed, it could lead
to an out of bounds write on the heap and potential code execution.
(CVE-2016-6250)

  * Multiple instances of undefined behavior due to arithmetic overflow were
found in libarchive. Specially crafted MTREE archives, Compress streams, or
ISO9660 vol ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"libarchive on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-September/msg00014.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"libarchive", rpm:"libarchive~3.1.2~10.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libarchive-debuginfo", rpm:"libarchive-debuginfo~3.1.2~10.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
