###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for perl CESA-2013:0685 centos5
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019668.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881700");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-28 09:49:47 +0530 (Thu, 28 Mar 2013)");
  script_cve_id("CVE-2012-5195", "CVE-2012-5526", "CVE-2012-6329", "CVE-2013-1667");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for perl CESA-2013:0685 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"perl on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Perl is a high-level programming language commonly used for system
  administration utilities and web programming.

  A heap overflow flaw was found in Perl. If a Perl application allowed
  user input to control the count argument of the string repeat operator, an
  attacker could cause the application to crash or, potentially, execute
  arbitrary code with the privileges of the user running the application.
  (CVE-2012-5195)

  A denial of service flaw was found in the way Perl's rehashing code
  implementation, responsible for recalculation of hash keys and
  redistribution of hash content, handled certain input. If an attacker
  supplied specially-crafted input to be used as hash keys by a Perl
  application, it could cause excessive memory consumption. (CVE-2013-1667)

  It was found that the Perl CGI module, used to handle Common Gateway
  Interface requests and responses, incorrectly sanitized the values for
  Set-Cookie and P3P headers. If a Perl application using the CGI module
  reused cookies values and accepted untrusted input from web browsers, a
  remote attacker could use this flaw to alter member items of the cookie or
  add new items. (CVE-2012-5526)

  It was found that the Perl Locale::Maketext module, used to localize Perl
  applications, did not properly handle backslashes or fully-qualified method
  names. An attacker could possibly use this flaw to execute arbitrary Perl
  code with the privileges of a Perl application that uses untrusted
  Locale::Maketext templates. (CVE-2012-6329)

  Red Hat would like to thank the Perl project for reporting CVE-2012-5195
  and CVE-2013-1667. Upstream acknowledges Tim Brown as the original
  reporter of CVE-2012-5195 and Yves Orton as the original reporter of
  CVE-2013-1667.

  All Perl users should upgrade to these updated packages, which contain
  backported patches to correct these issues. All running Perl programs
  must be restarted for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"perl", rpm:"perl~5.8.8~40.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-suidperl", rpm:"perl-suidperl~5.8.8~40.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
