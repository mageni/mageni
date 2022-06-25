###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for evince RHSA-2011:0009-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-January/msg00003.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870599");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-06-05 19:32:19 +0530 (Tue, 05 Jun 2012)");
  script_cve_id("CVE-2010-2640", "CVE-2010-2641", "CVE-2010-2642", "CVE-2010-2643");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for evince RHSA-2011:0009-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'evince'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"evince on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Evince is a document viewer.

  An array index error was found in the DeVice Independent (DVI) renderer's
  PK and VF font file parsers. A DVI file that references a specially-crafted
  font file could, when opened, cause Evince to crash or, potentially,
  execute arbitrary code with the privileges of the user running Evince.
  (CVE-2010-2640, CVE-2010-2641)

  A heap-based buffer overflow flaw was found in the DVI renderer's AFM font
  file parser. A DVI file that references a specially-crafted font file
  could, when opened, cause Evince to crash or, potentially, execute
  arbitrary code with the privileges of the user running Evince.
  (CVE-2010-2642)

  An integer overflow flaw was found in the DVI renderer's TFM font file
  parser. A DVI file that references a specially-crafted font file could,
  when opened, cause Evince to crash or, potentially, execute arbitrary code
  with the privileges of the user running Evince. (CVE-2010-2643)

  Note: The above issues are not exploitable unless an attacker can trick the
  user into installing a malicious font file.

  Red Hat would like to thank the Evince development team for reporting these
  issues.  Upstream acknowledges Jon Larimer of IBM X-Force as the original
  reporter of these issues.

  Users are advised to upgrade to these updated packages, which contain a
  backported patch to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"evince", rpm:"evince~2.28.2~14.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evince-debuginfo", rpm:"evince-debuginfo~2.28.2~14.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evince-dvi", rpm:"evince-dvi~2.28.2~14.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evince-libs", rpm:"evince-libs~2.28.2~14.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
