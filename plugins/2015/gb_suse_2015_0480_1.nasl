###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0480_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for bind SUSE-SU-2015:0480-1 (bind)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851035");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-16 18:37:03 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2014-0591", "CVE-2014-8500");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for bind SUSE-SU-2015:0480-1 (bind)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This bind updated fixes the following two security issues:

  *

  A flaw in delegation handling could be exploited to put named into
  an infinite loop. This has been addressed by placing limits on the number
  of levels of recursion named will allow (default 7), and the number of
  iterative queries that it will send (default 50) before terminating a
  recursive query (CVE-2014-8500, bnc#908994). The recursion depth limit is
  configured via the 'max-recursion-depth'
  option, and the query limit via the 'max-recursion-queries' option.

  *

  A flaw when handling malformed NSEC3-signed zones could lead named
  to a crash. (CVE-2014-0591, bnc#858639)

  Additionally, a non-security bug has been fixed:

  * Fix handling of TXT records in ldapdump (bnc#743758).

  Security Issues:

  * CVE-2014-8500

  * CVE-2014-0591

  Indications:

  Everybody should update.");
  script_tag(name:"affected", value:"bind on SUSE Linux Enterprise Server 11 SP1 LTSS");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLES11.0SP1")
{

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.6ESVR11W1~0.2.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.6ESVR11W1~0.2.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.6ESVR11W1~0.2.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.6ESVR11W1~0.2.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.6ESVR11W1~0.2.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ind-libs-32bit", rpm:"ind-libs-32bit~9.6ESVR11W1~0.2.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
