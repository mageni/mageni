###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_1842-01_kernel.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# RedHat Update for kernel RHSA-2017:1842-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871855");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-04 12:47:14 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2014-7970", "CVE-2014-7975", "CVE-2015-8839", "CVE-2015-8970",
                "CVE-2016-10088", "CVE-2016-10147", "CVE-2016-10200", "CVE-2016-6213",
                "CVE-2016-7042", "CVE-2016-7097", "CVE-2016-8645", "CVE-2016-9576",
                "CVE-2016-9588", "CVE-2016-9604", "CVE-2016-9685", "CVE-2016-9806",
                "CVE-2017-2596", "CVE-2017-2647", "CVE-2017-2671", "CVE-2017-5970",
                "CVE-2017-6001", "CVE-2017-6951", "CVE-2017-7187", "CVE-2017-7616",
                "CVE-2017-7889", "CVE-2017-8797", "CVE-2017-8890", "CVE-2017-9074",
                "CVE-2017-9075", "CVE-2017-9076", "CVE-2017-9077", "CVE-2017-9242");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for kernel RHSA-2017:1842-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
  kernel, the core of any Linux operating system. Security Fix(es): * An
  use-after-free flaw was found in the Linux kernel which enables a race condition
  in the L2TPv3 IP Encapsulation feature. A local user could use this flaw to
  escalate their privileges or crash the system. (CVE-2016-10200, Important) * A
  flaw was found that can be triggered in keyring_search_iterator in keyring.c if
  type- match is NULL. A local user could use this flaw to crash the system or,
  potentially, escalate their privileges. (CVE-2017-2647, Important) * It was
  found that the NFSv4 server in the Linux kernel did not properly validate layout
  type when processing NFSv4 pNFS LAYOUTGET and GETDEVICEINFO operands. A remote
  attacker could use this flaw to soft-lockup the system and thus cause denial of
  service. (CVE-2017-8797, Important) This update also fixes multiple Moderate and
  Low impact security issues: * CVE-2015-8839, CVE-2015-8970, CVE-2016-9576,
  CVE-2016-7042, CVE-2016-7097, CVE-2016-8645, CVE-2016-9576, CVE-2016-9588,
  CVE-2016-9806, CVE-2016-10088, CVE-2016-10147, CVE-2017-2596, CVE-2017-2671,
  CVE-2017-5970, CVE-2017-6001, CVE-2017-6951, CVE-2017-7187, CVE-2017-7616,
  CVE-2017-7889, CVE-2017-8890, CVE-2017-9074, CVE-2017-8890, CVE-2017-9075,
  CVE-2017-8890, CVE-2017-9076, CVE-2017-8890, CVE-2017-9077, CVE-2017-9242,
  CVE-2014-7970, CVE-2014-7975, CVE-2016-6213, CVE-2016-9604, CVE-2016-9685
  Documentation for these issues is available from the Release Notes document
  linked from the References section. Red Hat would like to thank Igor Redko
  (Virtuozzo) and Andrey Ryabinin (Virtuozzo) for reporting CVE-2017-2647 Igor
  Redko (Virtuozzo) and Vasily Averin (Virtuozzo) for reporting CVE-2015-8970
  Marco Grassi for reporting CVE-2016-8645 and Dmitry Vyukov (Google Inc.) for
  reporting CVE-2017-2596. The CVE-2016-7042 issue was discovered by Ondrej Kozina
  (Red Hat) the CVE-2016-7097 issue was discovered by Andreas Gruenbacher (Red
  Hat) and Jan Kara (SUSE) the CVE-2016-6213 and CVE-2016-9685 issues were
  discovered by Qian Cai (Red Hat) and the CVE-2016-9604 issue was discovered by
  David Howells (Red Hat). Additional Changes: For detailed information on other
  changes in this release, see the Red Hat Enterprise Linux 7.4 Release Notes
  linked from the References section.");
  script_tag(name:"affected", value:"kernel on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00017.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~693.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~693.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~693.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~693.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~3.10.0~693.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~693.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.10.0~693.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~3.10.0~693.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~693.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~693.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~693.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-debuginfo", rpm:"kernel-tools-debuginfo~3.10.0~693.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~693.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~693.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf-debuginfo", rpm:"perf-debuginfo~3.10.0~693.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~693.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf-debuginfo", rpm:"python-perf-debuginfo~3.10.0~693.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
