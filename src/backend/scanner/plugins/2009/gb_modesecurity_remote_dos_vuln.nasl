###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_modesecurity_remote_dos_vuln.nasl 12720 2018-12-08 13:43:47Z cfischer $
#
# ModSecurity Multiple Remote Denial of Service Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800626");
  script_version("$Revision: 12720 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-08 14:43:47 +0100 (Sat, 08 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-1902", "CVE-2009-1903");
  script_bugtraq_id(34096);
  script_name("ModSecurity Multiple Remote Denial of Service Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34256");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8241");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0703");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause denial of
  service.");

  script_tag(name:"affected", value:"ModSecurity version prior to 2.5.9 on Linux.");

  script_tag(name:"insight", value:"The multiple flaws are due to,

  - An error in the PDF XSS protection implementation which can be exploited
    to cause a crash via a specially crafted HTTP request.

  - NULL pointer dereference error when parsing multipart requests can be
    exploited to cause a crash via multipart content with a missing part header
    name.");

  script_tag(name:"solution", value:"Upgrade to version 2.5.9 or later.");

  script_tag(name:"summary", value:"This host is running ModSecurity and is prone to Denial of Service
  Vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("ModSecurity v[0-9]\\+.[0-9]\\+.[0-9]\\+");

modName = find_file(file_name:"mod_security2.so", file_path:"/", useregex:TRUE, regexpar:"$", sock:sock);
foreach binaryName (modName) {

  binaryName = chomp(binaryName);
  if(!binaryName) continue;

  arg = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string(0x22) + garg[3] + raw_string(0x22) + " " + binaryName;

  modsecVer = get_bin_version(full_prog_name:"grep", version_argv:arg, ver_pattern:"([0-9]+\.[0-9]+\.[0-9]+)", sock:sock);
  if(modsecVer[1]){
    if(version_is_less(version:modsecVer[1], test_version:"2.5.9")){
      report = report_fixed_ver(installed_version:modsecVer[1], fixed_version:"2.5.9", install_path:binaryName);
      security_message(port:0, data:report);
      ssh_close_connection();
      exit(0);
    }
  }
}

ssh_close_connection();
exit(0);