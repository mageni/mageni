###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2008_039.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for net-snmp SUSE-SA:2008:039
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "The net-snmp daemon implements the &quot;simple network management protocol&quot;.
  The version 3 of SNMP as implemented in net-snmp uses the length of the
  HMAC in a packet to verify against a local HMAC for authentication.
  An attacker can therefore send a SNMPv3 packet with a one byte HMAC and
  guess the correct first byte of the local HMAC with 256 packets (max).

  Additionally a buffer overflow in perl-snmp was fixed that can cause a
  denial-of-service/crash.";

tag_impact = "authentication bypass, denial-of-service";
tag_affected = "net-snmp on openSUSE 10.2, openSUSE 10.3, openSUSE 11.0, SUSE SLES 9, Novell Linux Desktop 9, Open Enterprise Server, Novell Linux POS 9, SUSE Linux Enterprise Desktop 10 SP1, SLE SDK 10 SP1, SLE SDK 10 SP2, SUSE Linux Enterprise Server 10 SP1, SUSE Linux Enterprise Desktop 10 SP2, SUSE Linux Enterprise Server 10 SP2";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.310860");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-0960", "CVE-2008-2292", "CVE-2008-1290", "CVE-2008-1291", "CVE-2008-1292");
  script_name( "SuSE Update for net-snmp SUSE-SA:2008:039");

  script_tag(name:"summary", value:"Check for the Version of net-snmp");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE10.3")
{

  if ((res = isrpmvuln(pkg:"libsnmp15", rpm:"libsnmp15~5.4.1~19.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.4.1~19.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.4.1~19.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.4.1~19.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snmp-mibs", rpm:"snmp-mibs~5.4.1~19.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.4.1~19.2", rls:"openSUSE10.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.4.rc2~8", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.4.rc2~8", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.4.rc2~8", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.4.rc2~8", rls:"openSUSE10.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDK10SP1")
{

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.24.3", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.24.3", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.24.3", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.24.3", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.1.3.1~0.22", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.1.3.1~0.22", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.1.3.1~0.22", rls:"SLESDK10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLPOS9")
{

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.26", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.26", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.26", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.26", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.24.3", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.24.3", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.24.3", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.24.3", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.1.3.1~0.22", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.1.3.1~0.22", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.1.3.1~0.22", rls:"NLPOS9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "OES")
{

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.26", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.26", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.26", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.26", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.24.3", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.24.3", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.24.3", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.24.3", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.1.3.1~0.22", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.1.3.1~0.22", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.1.3.1~0.22", rls:"OES")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES9")
{

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.26", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.26", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.26", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.26", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.24.3", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.24.3", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.24.3", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.24.3", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.1.3.1~0.22", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.1.3.1~0.22", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.1.3.1~0.22", rls:"SLES9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "LES10SP2")
{

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.26", rls:"LES10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.26", rls:"LES10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.26", rls:"LES10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.26", rls:"LES10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.24.3", rls:"LES10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.24.3", rls:"LES10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.24.3", rls:"LES10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.24.3", rls:"LES10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.1.3.1~0.22", rls:"LES10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.1.3.1~0.22", rls:"LES10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.1.3.1~0.22", rls:"LES10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "LES10SP1")
{

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.26", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.26", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.26", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.26", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.24.3", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.24.3", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.24.3", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.24.3", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.1.3.1~0.22", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.1.3.1~0.22", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.1.3.1~0.22", rls:"LES10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.26", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.26", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.26", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.26", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.24.3", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.24.3", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.24.3", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.24.3", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.1.3.1~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.1.3.1~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.1.3.1~0.22", rls:"NLDk9")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDK10SP2")
{

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.26", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.26", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.26", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.26", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.24.3", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.24.3", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.24.3", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.24.3", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.1.3.1~0.22", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.1.3.1~0.22", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.1.3.1~0.22", rls:"SLESDK10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP1")
{

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.24.3", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.24.3", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.24.3", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.24.3", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.1.3.1~0.22", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.1.3.1~0.22", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.1.3.1~0.22", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE11.0")
{

  if ((res = isrpmvuln(pkg:"libsnmp15", rpm:"libsnmp15~5.4.1~77.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.4.1~77.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.4.1~77.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.4.1~77.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"snmp-mibs", rpm:"snmp-mibs~5.4.1~77.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.4.1~77.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP2")
{

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.26", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.26", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.26", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.26", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.3.0.1~25.24.3", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.3.0.1~25.24.3", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.3.0.1~25.24.3", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-32bit", rpm:"net-snmp-32bit~5.3.0.1~25.24.3", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.1.3.1~0.22", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.1.3.1~0.22", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-SNMP", rpm:"perl-SNMP~5.1.3.1~0.22", rls:"SLESDk10SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
