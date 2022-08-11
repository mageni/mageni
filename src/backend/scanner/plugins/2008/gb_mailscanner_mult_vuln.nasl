###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mailscanner_mult_vuln.nasl 14240 2019-03-17 15:50:45Z cfischer $
#
# MailScanner Multiple Insecure Temporary Files Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800206");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-12-16 16:12:00 +0100 (Tue, 16 Dec 2008)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5312", "CVE-2008-5313");
  script_bugtraq_id(32557);
  script_name("MailScanner Multiple Insecure Temporary Files Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33117/");
  script_xref(name:"URL", value:"http://www.mailscanner.info/ChangeLog");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=506353");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2008/11/29/1");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes
  in the context of the application and can compromise a vulnerable system.");
  script_tag(name:"affected", value:"MailScanner version prior to 4.74.7-2 on Linux.");
  script_tag(name:"insight", value:"The flaws are due to,

  - Several autoupdate scripts for f-prot-autoupdate, clamav-autoupdate,
  panda-autoupdate, trend-autoupdate, bitdefender-wrapper, kaspersky-wrapper
  etc. use temporary files in an insecure manner.

  - The SpamAssassin and TNEF handlers use temporary files in an insecure manner.
  These can be exploited to affects local users to overwrite arbitrary files via
  symlink attacks.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to the latest MailScanner version 4.74.7-2 or later.");
  script_tag(name:"summary", value:"This host is installed with MailScanner and is prone to multiple
  vulnerabilities.");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(sock)
{
  send_cmd = ssh_cmd(socket:sock, cmd:"MailScanner -v", timeout:120);
  ssh_close_connection();
  if("MailScanner" >< send_cmd)
  {
    scanner_ver =  eregmatch(pattern:"MailScanner version ([0-9.]+)", string:send_cmd);
    if(scanner_ver[1] != NULL)
    {
      if(version_is_less_equal(version:scanner_ver[1], test_version:"4.74.7")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}
