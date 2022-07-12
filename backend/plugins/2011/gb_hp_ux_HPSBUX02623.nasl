###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_ux_HPSBUX02623.nasl 11739 2018-10-04 07:49:31Z cfischer $
#
# HP-UX Update for Kerberos HPSBUX02623
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
  script_xref(name:"URL", value:"http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02657328");
  script_oid("1.3.6.1.4.1.25623.1.0.835248");
  script_version("$Revision: 11739 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-04 09:49:31 +0200 (Thu, 04 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-21 14:59:01 +0100 (Fri, 21 Jan 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-1323", "CVE-2010-1324");
  script_name("HP-UX Update for Kerberos HPSBUX02623");
  script_tag(name:"summary", value:"The remote host is missing an update for the Kerberos package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("HP-UX Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/hp_hp-ux", "ssh/login/hp_pkgrev", re:"ssh/login/release=HPUX(11\.31|11\.23|11\.11)");

  script_tag(name:"impact", value:"Remote unauthorized modification");

  script_tag(name:"affected", value:"Kerberos on HP-UX B.11.11 running the Kerberos Client software versions prior to
  v1.3.5.11. HP-UX B.11.23 and B.11.31 running the Kerberos Client software
  versions prior to v1.6.2.09.");

  script_tag(name:"insight", value:"Potential security vulnerabilities have been identified on HP-UX running
  Kerberos. These vulnerabilities could be exploited remotely by an
  unauthorized user to modify data, prompts, or responses.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-hpux.inc");

release = hpux_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "HPUX11.31")
{

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-64SLIB-A", revision:"E.1.6.2.09", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-PRG-A", revision:"E.1.6.2.09", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-RUN-A", revision:"E.1.6.2.09", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-SHLIB-A", revision:"E.1.6.2.09", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5IA32SLIB-A", revision:"E.1.6.2.09", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5IA64SLIB-A", revision:"E.1.6.2.09", rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"KRB5-Client.KRB5-PRG", patch_list:['PHSS_41775'], rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"KRB5-Client.KRB5-64SLIB", patch_list:['PHSS_41775'], rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"KRB5-Client.KRB5-IA32SLIB", patch_list:['PHSS_41775'], rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"KRB5-Client.KRB5-IA64SLIB", patch_list:['PHSS_41775'], rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"KRB5-Client.KRB5-RUN", patch_list:['PHSS_41775'], rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"KRB5-Client.KRB5-SHLIB", patch_list:['PHSS_41775'], rls:"HPUX11.31")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "HPUX11.23")
{

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-64SLIB-A", revision:"D.1.6.2.09", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-PRG-A", revision:"D.1.6.2.09", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-RUN-A", revision:"D.1.6.2.09", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-SHLIB-A", revision:"D.1.6.2.09", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5IA32SLIB-A", revision:"D.1.6.2.09", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5IA64SLIB-A", revision:"D.1.6.2.09", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "HPUX11.11")
{

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-64SLIB-A", revision:"C.1.3.5.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-PRG-A", revision:"C.1.3.5.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-RUN-A", revision:"C.1.3.5.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"krb5client.KRB5-SHLIB-A", revision:"C.1.3.5.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
