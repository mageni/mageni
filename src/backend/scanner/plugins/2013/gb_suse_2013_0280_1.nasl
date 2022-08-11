###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2013_0280_1.nasl 14114 2019-03-12 11:48:52Z cfischer $
#
# SuSE Update for ruby openSUSE-SU-2013:0280-1 (ruby)
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
  script_tag(name:"affected", value:"ruby on openSUSE 11.4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"This update updates the RubyOnRails 2.3 stack to 2.3.16.

  Security and bugfixes were done, foremost: CVE-2013-0333: A
  JSON sql/code injection problem was fixed. CVE-2012-5664: A
  SQL Injection Vulnerability in Active Record was fixed.
  CVE-2012-2695: A SQL injection via nested hashes in
  conditions was fixed. CVE-2013-0155: Unsafe Query
  Generation Risk in Ruby on Rails was fixed. CVE-2013-0156:
  Multiple vulnerabilities in parameter parsing in Action
  Pack were fixed. CVE-2012-5664: options hashes should only
  be extracted if there are extra parameters CVE-2012-2695:
  Fix SQL injection via nested hashes in conditions
  CVE-2013-0156: Hash.from_xml raises when it encounters
  type='symbol' or type='yaml'. Use Hash.from_trusted_xml to
  parse this XM");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2013-02/msg00005.html");
  script_oid("1.3.6.1.4.1.25623.1.0.850400");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-11 18:29:34 +0530 (Mon, 11 Mar 2013)");
  script_cve_id("CVE-2012-2695", "CVE-2012-5664", "CVE-2013-0155", "CVE-2013-0156",
                "CVE-2013-0333");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("SuSE Update for ruby openSUSE-SU-2013:0280-1 (ruby)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE11\.4");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"rubygem-actionmailer-2_3", rpm:"rubygem-actionmailer-2_3~2.3.16~0.16.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-actionmailer-2_3-doc", rpm:"rubygem-actionmailer-2_3-doc~2.3.16~0.16.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-actionmailer-2_3-testsuite", rpm:"rubygem-actionmailer-2_3-testsuite~2.3.16~0.16.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-actionpack-2_3", rpm:"rubygem-actionpack-2_3~2.3.16~0.23.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-actionpack-2_3-doc", rpm:"rubygem-actionpack-2_3-doc~2.3.16~0.23.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-actionpack-2_3-testsuite", rpm:"rubygem-actionpack-2_3-testsuite~2.3.16~0.23.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-activerecord-2_3", rpm:"rubygem-activerecord-2_3~2.3.16~0.19.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-activerecord-2_3-doc", rpm:"rubygem-activerecord-2_3-doc~2.3.16~0.19.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-activerecord-2_3-testsuite", rpm:"rubygem-activerecord-2_3-testsuite~2.3.16~0.19.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-activeresource-2_3", rpm:"rubygem-activeresource-2_3~2.3.16~0.16.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-activeresource-2_3-doc", rpm:"rubygem-activeresource-2_3-doc~2.3.16~0.16.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-activeresource-2_3-testsuite", rpm:"rubygem-activeresource-2_3-testsuite~2.3.16~0.16.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-activesupport-2_3", rpm:"rubygem-activesupport-2_3~2.3.16~0.16.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-activesupport-2_3-doc", rpm:"rubygem-activesupport-2_3-doc~2.3.16~0.16.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-rack", rpm:"rubygem-rack~1.1.5~0.8.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-rails-2_3", rpm:"rubygem-rails-2_3~2.3.16~0.12.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-rails-2_3-doc", rpm:"rubygem-rails-2_3-doc~2.3.16~0.12.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-actionmailer", rpm:"rubygem-actionmailer~2.3.16~0.6.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-actionpack", rpm:"rubygem-actionpack~2.3.16~0.6.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-activerecord", rpm:"rubygem-activerecord~2.3.16~0.6.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-activeresource", rpm:"rubygem-activeresource~2.3.16~0.6.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rubygem-activesupport", rpm:"rubygem-activesupport~2.3.16~0.6.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ubygem-rails", rpm:"ubygem-rails~2.3.16~0.6.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
