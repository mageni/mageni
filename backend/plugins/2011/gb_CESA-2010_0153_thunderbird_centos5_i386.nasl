###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for thunderbird CESA-2010:0153 centos5 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-March/016584.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880629");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1571", "CVE-2009-3076", "CVE-2009-3075", "CVE-2009-3072", "CVE-2009-0689", "CVE-2009-3077", "CVE-2009-3380", "CVE-2010-0159", "CVE-2009-3979", "CVE-2009-3274", "CVE-2009-2463", "CVE-2009-2462", "CVE-2009-2470", "CVE-2009-2466", "CVE-2009-3376");
  script_name("CentOS Update for thunderbird CESA-2010:0153 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"thunderbird on CentOS 5");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the processing of malformed HTML mail content.
  An HTML mail message containing malicious content could cause Thunderbird
  to crash or, potentially, execute arbitrary code with the privileges of the
  user running Thunderbird. (CVE-2009-2462, CVE-2009-2463, CVE-2009-2466,
  CVE-2009-3072, CVE-2009-3075, CVE-2009-3380, CVE-2009-3979, CVE-2010-0159)

  A use-after-free flaw was found in Thunderbird. An attacker could use this
  flaw to crash Thunderbird or, potentially, execute arbitrary code with the
  privileges of the user running Thunderbird. (CVE-2009-3077)

  A heap-based buffer overflow flaw was found in the Thunderbird string to
  floating point conversion routines. An HTML mail message containing
  malicious JavaScript could crash Thunderbird or, potentially, execute
  arbitrary code with the privileges of the user running Thunderbird.
  (CVE-2009-0689)

  A use-after-free flaw was found in Thunderbird. Under low memory
  conditions, viewing an HTML mail message containing malicious content could
  result in Thunderbird executing arbitrary code with the privileges of the
  user running Thunderbird. (CVE-2009-1571)

  A flaw was found in the way Thunderbird created temporary file names for
  downloaded files. If a local attacker knows the name of a file Thunderbird
  is going to download, they can replace the contents of that file with
  arbitrary contents. (CVE-2009-3274)

  A flaw was found in the way Thunderbird displayed a right-to-left override
  character when downloading a file. In these cases, the name displayed in
  the title bar differed from the name displayed in the dialog body. An
  attacker could use this flaw to trick a user into downloading a file that
  has a file name or extension that is different from what the user expected.
  (CVE-2009-3376)

  A flaw was found in the way Thunderbird processed SOCKS5 proxy replies. A
  malicious SOCKS5 server could send a specially-crafted reply that would
  cause Thunderbird to crash. (CVE-2009-2470)

  Descriptions in the dialogs when adding and removing PKCS #11 modules were
  not informative. An attacker able to trick a user into installing a
  malicious PKCS #11 module could use this flaw to install their own
  Certificate Authority certificates on a user's machine, making it possible
  to trick the user into believing they are viewing trusted content or,
  potentially, execute arbitrary code with the privileges of the user running
  Thunderbird. (CVE-2009-3076)

  All Thunderbird users should upgrade to this updated package, which
  resolves these issues. All running instances of Thunderbird must be
  restarted for the update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~2.0.0.24~2.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
