###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_1594_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for libxml2 openSUSE-SU-2016:1594-1 (libxml2)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851340");
  script_version("2019-03-29T08:13:51+0000");
  script_tag(name:"last_modification", value:"2019-03-29 08:13:51 +0000 (Fri, 29 Mar 2019)");
  script_tag(name:"creation_date", value:"2016-06-17 05:19:58 +0200 (Fri, 17 Jun 2016)");
  script_cve_id("CVE-2016-1762", "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835",
                "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839",
                "CVE-2016-1840", "CVE-2016-3627", "CVE-2016-3705", "CVE-2016-4483");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for libxml2 openSUSE-SU-2016:1594-1 (libxml2)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update brings libxml2 to version 2.9.4.

  These security issues were fixed:

  - CVE-2016-3627: The xmlStringGetNodeList function in tree.c, when used in
  recovery mode, allowed context-dependent attackers to cause a denial of
  service (infinite recursion, stack consumption, and application crash)
  via a crafted XML document (bsc#972335).

  - CVE-2016-1833: libxml2 allowed remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via a crafted XML
  document, a different vulnerability than CVE-2016-1834, CVE-2016-1836,
  CVE-2016-1837, CVE-2016-1838, CVE-2016-1839, and CVE-2016-1840
  (bsc#981108).

  - CVE-2016-1835: libxml2 allowed remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via a crafted XML
  document (bsc#981109).

  - CVE-2016-1837: libxml2 allowed remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via a crafted XML
  document, a different vulnerability than CVE-2016-1833, CVE-2016-1834,
  CVE-2016-1836, CVE-2016-1838, CVE-2016-1839, and CVE-2016-1840
  (bsc#981111).

  - CVE-2016-1836: libxml2 allowed remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via a crafted XML
  document, a different vulnerability than CVE-2016-1833, CVE-2016-1834,
  CVE-2016-1837, CVE-2016-1838, CVE-2016-1839, and CVE-2016-1840
  (bsc#981110).

  - CVE-2016-1839: libxml2 allowed remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via a crafted XML
  document, a different vulnerability than CVE-2016-1833, CVE-2016-1834,
  CVE-2016-1836, CVE-2016-1837, CVE-2016-1838, and CVE-2016-1840
  (bsc#981114).

  - CVE-2016-1838: libxml2 allowed remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via a crafted XML
  document, a different vulnerability than CVE-2016-1833, CVE-2016-1834,
  CVE-2016-1836, CVE-2016-1837, CVE-2016-1839, and CVE-2016-1840
  (bsc#981112).

  - CVE-2016-1840: libxml2 allowed remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via a crafted XML
  document, a different vulnerability than CVE-2016-1833, CVE-2016-1834,
  CVE-2016-1836, CVE-2016-1837, CVE-2016-1838, and CVE-2016-1839
  (bsc#981115).

  - CVE-2016-4483: out-of-bounds read parsing an XML using recover mode
  (bnc#978395).

  - CVE-2016-1834: libxml2 allowed remote attackers to execute arbitrary
  code or cause a denial of service (memory corruption) via a crafted XML
  document, a different vulnerability than CVE-2016-1833, CVE-2016-1836,
 ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"libxml2 on openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-2-debuginfo", rpm:"libxml2-2-debuginfo~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-debugsource", rpm:"libxml2-debugsource~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-tools-debuginfo", rpm:"libxml2-tools-debuginfo~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libxml2", rpm:"python-libxml2~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libxml2-debuginfo", rpm:"python-libxml2-debuginfo~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libxml2-debugsource", rpm:"python-libxml2-debugsource~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-2-32bit", rpm:"libxml2-2-32bit~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-2-debuginfo-32bit", rpm:"libxml2-2-debuginfo-32bit~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-devel-32bit", rpm:"libxml2-devel-32bit~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-doc", rpm:"libxml2-doc~2.9.4~7.17.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
