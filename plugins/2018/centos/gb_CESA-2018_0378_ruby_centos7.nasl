###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_0378_ruby_centos7.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for ruby CESA-2018:0378 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882847");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-03-14 08:29:25 +0100 (Wed, 14 Mar 2018)");
  script_cve_id("CVE-2017-0898", "CVE-2017-0899", "CVE-2017-0900", "CVE-2017-0901",
                "CVE-2017-0902", "CVE-2017-0903", "CVE-2017-10784", "CVE-2017-14033",
                "CVE-2017-14064", "CVE-2017-17405", "CVE-2017-17790");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for ruby CESA-2018:0378 centos7");
  script_tag(name:"summary", value:"Check the version of ruby");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Ruby is an extensible, interpreted,
object-oriented, scripting language. It has features to process text files and
to perform system management tasks.

Security Fix(es):

  * It was discovered that the Net::FTP module did not properly process
filenames in combination with certain operations. A remote attacker could
exploit this flaw to execute arbitrary commands by setting up a malicious
FTP server and tricking a user or Ruby application into downloading files
with specially crafted names using the Net::FTP module. (CVE-2017-17405)

  * A buffer underflow was found in ruby's sprintf function. An attacker,
with ability to control its format string parameter, could send a specially
crafted string that would disclose heap memory or crash the interpreter.
(CVE-2017-0898)

  * It was found that rubygems did not sanitize gem names during installation
of a given gem. A specially crafted gem could use this flaw to install
files outside of the regular directory. (CVE-2017-0901)

  * A vulnerability was found where rubygems did not sanitize DNS responses
when requesting the hostname of the rubygems server for a domain, via a
_rubygems._tcp DNS SRV query. An attacker with the ability to manipulate
DNS responses could direct the gem command towards a different domain.
(CVE-2017-0902)

  * A vulnerability was found where the rubygems module was vulnerable to an
unsafe YAML deserialization when inspecting a gem. Applications inspecting
gem files without installing them can be tricked to execute arbitrary code
in the context of the ruby interpreter. (CVE-2017-0903)

  * It was found that WEBrick did not sanitize all its log messages. If logs
were printed in a terminal, an attacker could interact with the terminal
via the use of escape sequences. (CVE-2017-10784)

  * It was found that the decode method of the OpenSSL::ASN1 module was
vulnerable to buffer underrun. An attacker could pass a specially crafted
string to the application in order to crash the ruby interpreter, causing a
denial of service. (CVE-2017-14033)

  * A vulnerability was found where rubygems did not properly sanitize gems'
specification text. A specially crafted gem could interact with the
terminal via the use of escape sequences. (CVE-2017-0899)

  * It was found that rubygems could use an excessive amount of CPU while
parsing a sufficiently long gem summary. A specially crafted gem from a gem
repository could freeze gem commands attempting to parse its summary.
(CVE-2017-0900)

  * A buffer overflow vulnerability was found in the JSON extension of ruby.
An attacker with the ability to pass a specially crafted JSON input to the
extension could use this flaw to ex ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"ruby on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-March/022791.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~2.0.0.648~33.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~2.0.0.648~33.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-doc", rpm:"ruby-doc~2.0.0.648~33.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-bigdecimal", rpm:"rubygem-bigdecimal~1.2.0~33.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-io-console", rpm:"rubygem-io-console~0.4.2~33.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-json", rpm:"rubygem-json~1.7.7~33.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-minitest", rpm:"rubygem-minitest~4.3.2~33.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-psych", rpm:"rubygem-psych~2.0.0~33.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-rake", rpm:"rubygem-rake~0.9.6~33.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-rdoc", rpm:"rubygem-rdoc~4.0.0~33.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygems", rpm:"rubygems~2.0.14.1~33.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygems-devel", rpm:"rubygems-devel~2.0.14.1~33.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~2.0.0.648~33.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~2.0.0.648~33.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-tcltk", rpm:"ruby-tcltk~2.0.0.648~33.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
