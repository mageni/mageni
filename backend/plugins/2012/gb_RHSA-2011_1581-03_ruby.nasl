###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for ruby RHSA-2011:1581-03
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-December/msg00012.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870640");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:38:32 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-2705", "CVE-2011-3009", "CVE-2011-2686");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("RedHat Update for ruby RHSA-2011:1581-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"ruby on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Ruby is an extensible, interpreted, object-oriented, scripting language. It
  has features to process text files and to do system management tasks.

  It was found that Ruby did not reinitialize the PRNG (pseudorandom number
  generator) after forking a child process. This could eventually lead to the
  PRNG returning the same result twice. An attacker keeping track of the
  values returned by one child process could use this flaw to predict the
  values the PRNG would return in other child processes (as long as the
  parent process persisted). (CVE-2011-3009)

  A flaw was found in the Ruby SecureRandom module. When using the
  SecureRandom.random_bytes class, the PRNG state was not modified after
  forking a child process. This could eventually lead to
  SecureRandom.random_bytes returning the same string more than once. An
  attacker keeping track of the strings returned by one child process could
  use this flaw to predict the strings SecureRandom.random_bytes would return
  in other child processes (as long as the parent process persisted).
  (CVE-2011-2705)

  This update also fixes the following bugs:

  * The ruby package has been upgraded to upstream point release 1.8.7-p352,
  which provides a number of bug fixes over the previous version. (BZ#706332)

  * The MD5 message-digest algorithm is not a FIPS-approved algorithm.
  Consequently, when a Ruby script attempted to calculate an MD5 checksum in
  FIPS mode, the interpreter terminated unexpectedly. This bug has been fixed
  and an exception is now raised in the described scenario. (BZ#717709)

  * Due to inappropriately handled line continuations in the mkconfig.rb
  source file, an attempt to build the ruby package resulted in unexpected
  termination. An upstream patch has been applied to address this issue and
  the ruby package can now be built properly. (BZ#730287)

  * When the 32-bit ruby-libs library was installed on a 64-bit machine, the
  mkmf library failed to load various modules necessary for building
  Ruby-related packages. This bug has been fixed and mkmf now works properly
  in the described scenario. (BZ#674787)

  * Previously, the load paths for scripts and binary modules were duplicated
  on the i386 architecture. Consequently, an ActiveSupport test failed. With
  this update, the load paths are no longer stored in duplicates on the i386
  architecture. (BZ#722887)

  This update also adds the following enhancement:

  * With this update, SystemTap probes have been added to the ruby package.
  (BZ#673162)

  All users of ruby are advised to upgrade to these updated packages, which
  resolve these issues and add this enhancement.");
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

  if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.7.352~3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-debuginfo", rpm:"ruby-debuginfo~1.8.7.352~3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~1.8.7.352~3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~1.8.7.352~3.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
