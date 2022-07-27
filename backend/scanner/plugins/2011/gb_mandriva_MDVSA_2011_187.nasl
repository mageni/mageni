###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for php-pear MDVSA-2011:187 (php-pear)
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
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-12/msg00012.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831508");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-12-16 11:14:24 +0530 (Fri, 16 Dec 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2007-2519", "CVE-2011-1072");
  script_name("Mandriva Update for php-pear MDVSA-2011:187 (php-pear)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-pear'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(mes5|2010\.1)");
  script_tag(name:"affected", value:"php-pear on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"A vulnerability has been discovered and corrected in php-pear:
  The installer in PEAR before 1.9.2 allows local users to overwrite
  arbitrary files via a symlink attack on the package.xml file,
  related to the (1) download_dir, (2) cache_dir, (3) tmp_dir, and
  (4) pear-build-download directories, a different vulnerability than
  CVE-2007-2519 (CVE-2011-1072).

  This advisory provides PEAR 1.9.4 which is not vulnerable to this
  issue.

  Additionally for Mandriva Enterprise Server 5 many new or updated
  PEAR packages is being provided with the latest versions of respective
  packages as well as mitigating various dependency issues.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"php-pear", rpm:"php-pear~1.9.4~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Auth", rpm:"php-pear-Auth~1.6.4~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Auth_RADIUS", rpm:"php-pear-Auth_RADIUS~1.0.7~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Auth_SASL", rpm:"php-pear-Auth_SASL~1.0.6~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Cache_Lite", rpm:"php-pear-Cache_Lite~1.7.12~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Console_ProgressBar", rpm:"php-pear-Console_ProgressBar~0.5.2beta~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Crypt_CHAP", rpm:"php-pear-Crypt_CHAP~1.5.0~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date", rpm:"php-pear-Date~1.5.0a2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays", rpm:"php-pear-Date_Holidays~0.21.5~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays_Austria", rpm:"php-pear-Date_Holidays_Austria~0.1.3~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays_Brazil", rpm:"php-pear-Date_Holidays_Brazil~0.1.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays_Denmark", rpm:"php-pear-Date_Holidays_Denmark~0.1.3~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays_Discordian", rpm:"php-pear-Date_Holidays_Discordian~0.1.1~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays_EnglandWales", rpm:"php-pear-Date_Holidays_EnglandWales~0.1.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays_Germany", rpm:"php-pear-Date_Holidays_Germany~0.1.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays_Iceland", rpm:"php-pear-Date_Holidays_Iceland~0.1.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays_Italy", rpm:"php-pear-Date_Holidays_Italy~0.1.1~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays_Japan", rpm:"php-pear-Date_Holidays_Japan~0.1.1~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays_Netherlands", rpm:"php-pear-Date_Holidays_Netherlands~0.1.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays_Norway", rpm:"php-pear-Date_Holidays_Norway~0.1.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays_PHPdotNet", rpm:"php-pear-Date_Holidays_PHPdotNet~0.1.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays_Romania", rpm:"php-pear-Date_Holidays_Romania~0.1.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays_Slovenia", rpm:"php-pear-Date_Holidays_Slovenia~0.1.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays_Sweden", rpm:"php-pear-Date_Holidays_Sweden~0.1.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays_Ukraine", rpm:"php-pear-Date_Holidays_Ukraine~0.1.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays_UNO", rpm:"php-pear-Date_Holidays_UNO~0.1.3~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Date_Holidays_USA", rpm:"php-pear-Date_Holidays_USA~0.1.1~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-DB", rpm:"php-pear-DB~1.7.14~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-DB_DataObject", rpm:"php-pear-DB_DataObject~1.9.6~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-File_Passwd", rpm:"php-pear-File_Passwd~1.1.7~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-File_SMBPasswd", rpm:"php-pear-File_SMBPasswd~1.0.3~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-HTTP_Client", rpm:"php-pear-HTTP_Client~1.2.1~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-HTTP_Request", rpm:"php-pear-HTTP_Request~1.4.4~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-HTTP_Request2", rpm:"php-pear-HTTP_Request2~2.0.0~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Image_GraphViz", rpm:"php-pear-Image_GraphViz~1.3.0~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Log", rpm:"php-pear-Log~1.12.7~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Mail", rpm:"php-pear-Mail~1.2.0~0.b1.0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Mail_Mime", rpm:"php-pear-Mail_Mime~1.8.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Mail_mimeDecode", rpm:"php-pear-Mail_mimeDecode~1.5.5~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Math_BigInteger", rpm:"php-pear-Math_BigInteger~1.0.0~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-MDB2", rpm:"php-pear-MDB2~2.5.0~0.0.b3.0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-MDB2_Driver_mysql", rpm:"php-pear-MDB2_Driver_mysql~1.5.0~0.0.b3.0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-MDB2_Driver_mysqli", rpm:"php-pear-MDB2_Driver_mysqli~1.5.0~0.0.b3.0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-MDB2_Driver_pgsql", rpm:"php-pear-MDB2_Driver_pgsql~1.5.0~0.0.b3.0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-MDB2_Driver_sqlite", rpm:"php-pear-MDB2_Driver_sqlite~1.5.0~0.0.b3.0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Net_DIME", rpm:"php-pear-Net_DIME~1.0.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Net_IDNA", rpm:"php-pear-Net_IDNA~0.8.1~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Net_IDNA2", rpm:"php-pear-Net_IDNA2~0.1.1~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Net_IPv4", rpm:"php-pear-Net_IPv4~1.3.4~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Net_LDAP2", rpm:"php-pear-Net_LDAP2~2.0.10~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Net_POP3", rpm:"php-pear-Net_POP3~1.3.8~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Net_SMTP", rpm:"php-pear-Net_SMTP~1.6.1~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Net_Socket", rpm:"php-pear-Net_Socket~1.0.10~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Net_URL2", rpm:"php-pear-Net_URL2~2.0.0~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Net_Vpopmaild", rpm:"php-pear-Net_Vpopmaild~0.3.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Numbers_Words", rpm:"php-pear-Numbers_Words~0.16.3~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-OLE", rpm:"php-pear-OLE~1.0.0~0.RC1.0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-PEAR_Command_Packaging", rpm:"php-pear-PEAR_Command_Packaging~0.2.0~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Spreadsheet_Excel_Writer", rpm:"php-pear-Spreadsheet_Excel_Writer~0.9.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-System_Command", rpm:"php-pear-System_Command~1.0.7~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-Validate", rpm:"php-pear-Validate~0.8.4~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-XML_Parser", rpm:"php-pear-XML_Parser~1.3.4~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-XML_RPC2", rpm:"php-pear-XML_RPC2~1.1.1~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-XML_Serializer", rpm:"php-pear-XML_Serializer~0.20.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-XML_XSLT_Wrapper", rpm:"php-pear-XML_XSLT_Wrapper~0.2.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"php-pear", rpm:"php-pear~1.9.4~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
