###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_modsecurity_sec_bypass_vuln.nasl 12720 2018-12-08 13:43:47Z cfischer $
#
# ModSecurity 'SecCacheTransformations' Security Bypass Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2008 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900414");
  script_version("$Revision: 12720 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-08 14:43:47 +0100 (Sat, 08 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5676");
  script_bugtraq_id(31672);
  script_name("ModSecurity 'SecCacheTransformations' Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Web Servers");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32146");
  script_xref(name:"URL", value:"http://blog.modsecurity.org/2008/08/transformation.html");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary codes in
  the context of the web application and bypass certain security restrictions.");

  script_tag(name:"affected", value:"ModSecurity version from 2.5.0 to 2.5.5 on Linux.");

  script_tag(name:"insight", value:"This flaw is due an error within the transformation caching which can cause
  evasion into ModSecurity. These can be exploited when SecCacheTransformations
  is enabled.");

  script_tag(name:"solution", value:"Upgrade to version 2.5.6 or later.");

  script_tag(name:"summary", value:"This host is running ModSecurity and is prone to Security Bypass
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

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

modName = find_file(file_name:"mod_security.so", file_path:"/", useregex:TRUE, regexpar:"$", sock:sock);
foreach binaryName (modName) {

  binaryName = chomp(binaryName);
  if(!binaryName) continue;

  arg = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string(0x22) + garg[3] + raw_string(0x22) + " " + binaryName;

  modsecVer = get_bin_version(full_prog_name:"grep", version_argv:arg, ver_pattern:"([0-9]+\.[0-9]+\.[0-9]+)", sock:sock);
  if(modsecVer[1]){
    if(version_in_range(version:modsecVer[1], test_version:"2.5.0", test_version2:"2.5.5")){
      report = report_fixed_ver(installed_version:modsecVer[1], fixed_version:"2.5.6", install_path:binaryName);
      security_message(port:0, data:report);
      ssh_close_connection();
      exit(0);
    }
  }
}

ssh_close_connection();
exit(0);